// Independently ordered receipt and selected-RIB values exercise the control
// bank lifetime contract. The fixture owns copied advertisements and identities;
// forwarding selection itself is tested against real RIBs in separate fixtures.
#include "router/isis_interlevel_export_state.hpp"
#include <source_location>
#include <stdexcept>
namespace {
using namespace router;
using namespace router::isis;
void require(bool value, std::source_location where = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS export bank invariant at " + std::to_string(where.line()));
}
void build(InterlevelExportState &state, std::uint64_t publication, std::uint64_t entity) {
  require(state.begin_routes(publication));
  auto *bank = state.building_templates(); require(bank != nullptr);
  PrefixAdvertisement four;
  four.origin = {1U,2U,3U,4U,5U,6U,0U,0U}; four.level = 1U; four.metric = 10U;
  four.prefix = *ip::parse_ip_prefix(publication == 11U ? "192.0.2.1/32" : "192.0.2.2/32");
  four.attributes_size = 3U;
  const std::array<std::uint8_t,3U> attributes{4U,1U,0x20U};
  const auto first = bank->append(four,{0U,17U,0U},{0U,5U,entity},attributes);
  require(first.status == InterlevelTemplateStatus::applied);
  auto six = four; six.prefix = *ip::parse_ip_prefix("2001:db8:9::1/128"); six.attributes_size = 0U;
  const auto second = bank->append(six,{0U,23U,0U},{1U,6U,10U},{});
  require(second.status == InterlevelTemplateStatus::applied);
  for (const auto index : {first.index,first.index,InterlevelTemplates::no_template})
    require(bank->map_candidate(0U,index) == InterlevelTemplateStatus::applied);
  require(bank->map_candidate(1U,second.index) == InterlevelTemplateStatus::applied);
  require(state.route_published(publication) && !state.building_templates());
}
routing::IsisRouteSelection selection(std::uint64_t publication, std::uint64_t epoch,
    std::uint64_t revision, std::uint64_t four = 3U, std::uint64_t six = 1U) {
  routing::IsisRouteSelection value;
  value.identity = {{0U,1U},publication,epoch,revision}; value.counts = {3U,1U};
  value.selected[0U][0U] = four; value.selected[1U][0U] = six;
  return value;
}
}
void isis_interlevel_export_state_tests() {
  const lab::DeviceHandle device{0U,1U};
  const InterlevelTemplateBudget budget{4U,64U,4U};
  std::array owners{InterlevelEligibility{5U,9U,3U},InterlevelEligibility{6U,10U,3U}};
  InterlevelExportState state(device,budget);
  require(state.can_publish_routes() && !state.begin_routes(0U));
  build(state,11U,9U);
  require(!state.can_publish_routes() && !state.confirm_routes(99U));
  // The actual-FIB selection certificate may precede its separate receipt.
  auto result = state.accept(selection(11U,3U,1U),3U,owners);
  require(result.status == InterlevelApplyStatus::applied && result.dirty.test(0U) && result.dirty.test(1U));
  require(state.active_templates().publication() == 11U && state.selected(0U) && state.selected(1U));
  require(state.can_publish_routes() && state.confirm_routes(11U) && state.confirm_routes(11U) && !state.refuse_routes(11U));
  require(state.accept(selection(11U,3U,1U),3U,owners).status == InterlevelApplyStatus::stale);
  require(state.accept(selection(11U,2U,2U),3U,owners).status == InterlevelApplyStatus::stale);
  auto wrong_device = selection(11U,3U,2U); ++wrong_device.identity.device.generation;
  require(state.accept(wrong_device,3U,owners).status == InterlevelApplyStatus::stale);
  result = state.accept(selection(11U,3U,2U,4U,0U),3U,owners);
  require(result.status == InterlevelApplyStatus::applied && result.dirty.count() == 2U && !state.selected(0U) && !state.selected(1U));
  require(state.accept(selection(11U,3U,3U,1U,0U),3U,owners).status == InterlevelApplyStatus::applied && state.selected(0U));
  owners[0U].families = 0U;
  require(state.reconcile(owners).dirty.test(0U) && !state.selected(0U));
  owners[0U].families = 3U;
  require(state.reconcile(owners).dirty.none() && !state.selected(0U));
  require(state.accept(selection(11U,3U,4U,1U,0U),4U,owners).status == InterlevelApplyStatus::stale && !state.selected(0U));
  require(state.accept(selection(11U,4U,4U,1U,0U),4U,owners).status == InterlevelApplyStatus::applied && state.selected(0U));
  ++owners[0U].entity;
  require(state.reconcile(owners).dirty.test(0U) && !state.selected(0U));
  const auto recovered = state.checkpoint();
  InterlevelExportState after_recovery(device,budget);
  require(after_recovery.restore(recovered,owners) && !after_recovery.selected(0U));
  // The opposite order keeps the pending payload until selection arrives and
  // prevents an older active-publication value from reversing its FIB proof.
  build(state,12U,10U);
  require(state.confirm_routes(12U) && state.pending_confirmed() && !state.can_publish_routes());
  require(!state.can_retain_source(11U) && state.can_retain_source(12U) && state.confirm_retained_source(12U));
  require(state.accept(selection(11U,4U,5U),4U,owners).status == InterlevelApplyStatus::stale);
  result = state.accept(selection(12U,4U,5U),4U,owners);
  require(result.status == InterlevelApplyStatus::applied && result.dirty.count() == 2U &&
      state.selected(0U) && state.selected(1U) && !state.pending_publication());
  require(state.active_templates().entries()[0U].advertisement.prefix == *ip::parse_ip_prefix("192.0.2.2/32"));
  const auto image = state.checkpoint();
  InterlevelExportState restored(device,budget);
  require(restored.restore(image,owners) && restored.selected(0U) && restored.selected(1U));
  const auto refuses = [&](auto corrupt) {
    auto changed = image; corrupt(changed);
    require(!restored.restore(changed,owners));
    require(restored.active_templates().publication() == 12U && restored.last_selection_revision() == 5U &&
        restored.selected(0U) && restored.selected(1U));
  };
  refuses([](auto &saved) { saved.selected[0U] = 2U; });
  refuses([](auto &saved) { saved.active.entries[0U].owner.entity = 9U; });
  refuses([](auto &saved) { saved.active.candidates[0U][0U] = 99U; });
  refuses([](auto &saved) { saved.pending_confirmed = true; });
  refuses([](auto &saved) { saved.last_selection_revision = 0U; });
  refuses([](auto &saved) { ++saved.device.generation; });
  owners[0U].families = 2U;
  require(!restored.restore(image,owners));
  require(state.reconcile(owners).dirty.test(0U) && !state.selected(0U) && state.selected(1U));
  build(state,13U,10U);
  require(state.refuse_routes(13U) && !state.refuse_routes(13U) && state.active_templates().publication() == 12U);
  require(state.begin_routes(14U));
  bool refused_build_capture{};
  try { static_cast<void>(state.checkpoint()); } catch (const std::logic_error &) { refused_build_capture = true; }
  require(refused_build_capture && state.abort_build() && !state.abort_build() && !state.begin_routes(12U));
  require(state.begin_routes(14U) && state.route_published(14U) && state.confirm_routes(14U));
  routing::IsisRouteSelection empty; empty.identity = {device,14U,5U,6U};
  result = state.accept(empty,5U,owners);
  require(result.status == InterlevelApplyStatus::applied && result.dirty.test(1U) &&
      state.active_templates().entries().empty() && !state.selected(0U));
  build(state,15U,10U);
  require(state.confirm_routes(15U));
  const auto pending = state.checkpoint();
  InterlevelExportState resumed(device,budget);
  require(resumed.restore(pending,owners) && resumed.pending_confirmed() && !resumed.can_publish_routes());
  require(resumed.accept(selection(15U,5U,7U),5U,owners).status == InterlevelApplyStatus::applied &&
      !resumed.selected(0U) && resumed.selected(1U) && resumed.confirm_routes(15U));
  auto invalid = selection(15U,5U,8U); invalid.selected[0U][0U] = 8U;
  require(resumed.accept(invalid,5U,owners).status == InterlevelApplyStatus::invalid && resumed.last_selection_revision() == 7U);
}
