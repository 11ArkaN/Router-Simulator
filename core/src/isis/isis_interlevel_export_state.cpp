// The control shard alone advances installed export provenance. Two owned banks
// and copied selection values absorb channel reordering without lending source
// decision storage. Wire composition remains a separate instance responsibility.
// Source: ietf.isis.selected_interlevel_export
#include "router/isis_interlevel_export_state.hpp"
#include <algorithm>
#include <stdexcept>
namespace router::isis {
namespace {
lab::DeviceHandle checked_device(lab::DeviceHandle device) {
  if (!device.generation || device.index >= device_catalog::maximum_routers)
    throw std::invalid_argument("Invalid IS-IS export device");
  return device;
}
bool catalog_valid(std::span<const InterlevelEligibility> owners) noexcept {
  return owners.size() <= device_catalog::isis_instance_last + 1U &&
      std::all_of(owners.begin(),owners.end(),[](const auto &owner) {
        return !(owner.families & ~3U) && (!owner.families || (owner.admission && owner.entity >= owner.admission));
      });
}
bool eligible(const InterlevelTemplate &entry, std::span<const InterlevelEligibility> owners) noexcept {
  if (entry.owner.instance >= owners.size()) return false;
  const auto &owner = owners[entry.owner.instance];
  const auto family = entry.advertisement.prefix.network.family == ip::AddressFamily::ipv6 ? 2U : 1U;
  return owner.admission == entry.owner.admission && owner.entity == entry.owner.entity && (owner.families & family);
}
}
InterlevelExportState::InterlevelExportState(lab::DeviceHandle device, InterlevelTemplateBudget budget)
    : device_(checked_device(device)), budget_(budget), active_(std::make_unique<InterlevelTemplates>(budget)),
      pending_(std::make_unique<InterlevelTemplates>(budget)), selected_(std::make_unique<bool[]>(budget.prefixes)),
      scratch_(std::make_unique<bool[]>(budget.prefixes)) {}
bool InterlevelExportState::can_publish_routes() const noexcept { return !building_ && !pending_->publication(); }
bool InterlevelExportState::begin_routes(std::uint64_t publication) noexcept {
  if (!can_publish_routes() || publication <= active_->publication() || !pending_->begin(device_,publication)) return false;
  building_ = true; return true;
}
bool InterlevelExportState::route_published(std::uint64_t publication) noexcept {
  if (!building_ || pending_->publication() != publication) return false;
  building_ = false; return true;
}
bool InterlevelExportState::abort_build() noexcept {
  if (!building_) return false;
  pending_->clear(); building_ = false; return true;
}
bool InterlevelExportState::confirm_routes(std::uint64_t publication) noexcept {
  if (publication && publication == active_->publication()) return true;
  if (building_ || !publication || pending_->publication() != publication) return false;
  pending_confirmed_ = true; return true;
}
bool InterlevelExportState::refuse_routes(std::uint64_t publication) noexcept {
  if (building_ || !publication || pending_->publication() != publication || pending_confirmed_) return false;
  pending_->clear(); return true;
}
bool InterlevelExportState::can_retain_source(std::uint64_t publication) const noexcept {
  if (building_) return false;
  if (publication && publication == pending_->publication()) return true;
  return publication == active_->publication() && !pending_confirmed_;
}
bool InterlevelExportState::confirm_retained_source(std::uint64_t publication) noexcept {
  if (!can_retain_source(publication)) return false;
  if (publication && publication == pending_->publication()) pending_confirmed_ = true;
  return true;
}
InterlevelApplyResult InterlevelExportState::accept(const routing::IsisRouteSelection &selection,
    std::uint64_t epoch, std::span<const InterlevelEligibility> owners) noexcept {
  if (!routing::valid_isis_route_selection(selection) || !epoch || !catalog_valid(owners))
    return {InterlevelApplyStatus::invalid,{}};
  if (selection.identity.device != device_ || selection.identity.configuration_epoch != epoch ||
      selection.identity.revision <= last_revision_) return {};
  const bool pending = !building_ && pending_->publication() == selection.identity.publication;
  if (!pending && (active_->publication() != selection.identity.publication || pending_confirmed_)) return {};
  const auto &bank = pending ? *pending_ : *active_;
  if (!bank.select(selection,{scratch_.get(),bank.entries().size()})) return {InterlevelApplyStatus::invalid,{}};
  return apply_prepared(pending,selection.identity.revision,owners);
}
InterlevelApplyResult InterlevelExportState::apply_prepared(bool pending, std::uint64_t revision,
    std::span<const InterlevelEligibility> owners) noexcept {
  InterlevelApplyResult result{InterlevelApplyStatus::applied,{}};
  const auto &bank = pending ? *pending_ : *active_;
  for (std::size_t index{}; index < bank.entries().size(); ++index) {
    const auto &entry = bank.entries()[index];
    scratch_[index] = scratch_[index] && eligible(entry,owners);
    if (pending ? scratch_[index] : scratch_[index] != selected_[index]) result.dirty.set(entry.owner.instance);
  }
  if (pending) {
    for (std::size_t index{}; index < active_->entries().size(); ++index)
      if (selected_[index]) result.dirty.set(active_->entries()[index].owner.instance);
    active_.swap(pending_); pending_->clear(); pending_confirmed_ = false;
  }
  selected_.swap(scratch_); last_revision_ = revision;
  return result;
}
InterlevelApplyResult InterlevelExportState::reconcile(std::span<const InterlevelEligibility> owners) noexcept {
  if (!catalog_valid(owners)) return {InterlevelApplyStatus::invalid,{}};
  InterlevelApplyResult result{InterlevelApplyStatus::applied,{}};
  for (std::size_t index{}; index < active_->entries().size(); ++index)
    if (selected_[index] && !eligible(active_->entries()[index],owners)) {
      selected_[index] = false; result.dirty.set(active_->entries()[index].owner.instance);
    }
  return result;
}
bool InterlevelExportState::selected(std::size_t index) const noexcept {
  return index < active_->entries().size() && selected_[index];
}
InterlevelExportCheckpoint InterlevelExportState::checkpoint() const {
  if (building_) throw std::logic_error("IS-IS export capture cannot retain an unfinished build");
  InterlevelExportCheckpoint result;
  result.device = device_; result.active = active_->checkpoint(); result.pending = pending_->checkpoint();
  result.pending_confirmed = pending_confirmed_; result.last_selection_revision = last_revision_;
  result.selected.reserve(active_->entries().size());
  for (std::size_t index{}; index < active_->entries().size(); ++index)
    result.selected.push_back(static_cast<std::uint8_t>(selected_[index]));
  return result;
}
bool InterlevelExportState::restore(const InterlevelExportCheckpoint &saved,
    std::span<const InterlevelEligibility> owners) noexcept {
  if (saved.version != 1U || saved.device != device_ || !catalog_valid(owners) ||
      saved.selected.size() != saved.active.entries.size() ||
      (saved.active.publication && !saved.last_selection_revision) ||
      (!saved.active.publication && !saved.pending.publication && saved.last_selection_revision) ||
      (saved.pending.publication ? saved.pending.publication <= saved.active.publication :
          saved.pending_confirmed)) return false;
  try {
    auto active = std::make_unique<InterlevelTemplates>(budget_);
    auto pending = std::make_unique<InterlevelTemplates>(budget_);
    auto selected = std::make_unique<bool[]>(budget_.prefixes);
    auto scratch = std::make_unique<bool[]>(budget_.prefixes);
    if (!active->restore(saved.active,device_) || !pending->restore(saved.pending,device_)) return false;
    for (std::size_t index{}; index < saved.selected.size(); ++index) {
      if (saved.selected[index] > 1U || (saved.selected[index] && !eligible(active->entries()[index],owners))) return false;
      selected[index] = saved.selected[index] != 0U;
    }
    active_.swap(active); pending_.swap(pending); selected_.swap(selected); scratch_.swap(scratch);
    building_ = false; pending_confirmed_ = saved.pending_confirmed;
    last_revision_ = saved.last_selection_revision;
    return true;
  } catch (...) { return false; }
}
}
