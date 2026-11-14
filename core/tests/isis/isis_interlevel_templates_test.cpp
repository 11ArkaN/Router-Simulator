// Copied L1 attributes outlive their source decision and pending publication.
// Each fixture owns banks, candidate identities and selection values; no remote
// state or fabricated forwarding callback supplies export eligibility.
#include "router/isis_interlevel_templates.hpp"
#include <source_location>
#include <stdexcept>
namespace {
using namespace router;
using namespace router::isis;
void require(bool value, std::source_location where = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS interlevel template invariant at " + std::to_string(where.line()));
}
}
void isis_interlevel_templates_tests() {
  const InterlevelTemplateBudget budget{4U,64U,3U};
  const lab::DeviceHandle device{2U,7U};
  InterlevelTemplates pending(budget), installed(budget);
  const auto empty = pending.checkpoint();
  require(installed.restore(empty,device));
  require(!pending.begin({2U,0U},11U) && !pending.begin(device,0U));
  require(pending.begin(device,11U));
  PrefixAdvertisement four;
  four.origin = {1U,2U,3U,4U,5U,6U,0U,0U};
  four.prefix = *ip::parse_ip_prefix("192.0.2.1/32");
  four.metric = 10U; four.level = 1U; four.attributes_size = 15U;
  std::array<std::uint8_t,15U> attributes{4U,1U,0x20U,1U,4U,0U,0U,0U,7U,11U,4U,192U,0U,2U,9U};
  const auto first = pending.append(four,{0U,17U,0U},{0U,5U,9U},attributes);
  require(first.status == InterlevelTemplateStatus::applied && first.index == 0U);
  attributes[2U] = 0xffU;
  require(pending.attributes(0U)[2U] == 0x20U && pending.entries()[0U].distance.metric == 17U);
  auto six = four; six.prefix = *ip::parse_ip_prefix("2001:db8:9::/64");
  six.attributes_size = 0U; six.external = true;
  const auto second = pending.append(six,{0U,23U,0U},{1U,6U,10U},{});
  require(second.status == InterlevelTemplateStatus::applied && second.index == 1U);
  auto down = four; down.down = true;
  require(pending.append(down,{0U,17U,0U},{0U,5U,9U},attributes).status == InterlevelTemplateStatus::ineligible);
  auto unknown = four; unknown.level = 0U;
  require(pending.append(unknown,{0U,17U,0U},{0U,5U,9U},attributes).status == InterlevelTemplateStatus::invalid);
  auto level2 = four; level2.level = 2U;
  require(pending.append(level2,{1U,17U,0U},{0U,5U,9U},attributes).status == InterlevelTemplateStatus::ineligible);
  require(pending.append(four,{0U,17U,0U},{0U,9U,5U},attributes).status == InterlevelTemplateStatus::invalid);
  auto malformed = attributes; malformed[1U] = 255U;
  require(pending.append(four,{0U,17U,0U},{0U,5U,9U},malformed).status == InterlevelTemplateStatus::invalid);
  require(pending.entries().size() == 2U);
  require(pending.map_candidate(0U,0U) == InterlevelTemplateStatus::applied);
  require(pending.map_candidate(0U,0U) == InterlevelTemplateStatus::applied);
  require(pending.map_candidate(0U,InterlevelTemplates::no_template) == InterlevelTemplateStatus::applied);
  require(pending.map_candidate(0U,0U) == InterlevelTemplateStatus::capacity);
  require(pending.map_candidate(1U,0U) == InterlevelTemplateStatus::invalid);
  require(pending.map_candidate(1U,1U) == InterlevelTemplateStatus::applied);
  require(pending.map_candidate(2U,0U) == InterlevelTemplateStatus::invalid);
  routing::IsisRouteSelection selected;
  selected.identity = {device,11U,3U,1U};
  selected.counts = {3U,1U}; selected.selected[0U][0U] = 3U; selected.selected[1U][0U] = 1U;
  std::array<bool,2U> eligible{};
  require(pending.select(selected,eligible) && eligible[0U] && eligible[1U]);
  selected.selected[0U][0U] = 4U; selected.selected[1U][0U] = 0U;
  require(pending.select(selected,eligible) && !eligible[0U] && !eligible[1U]);
  selected.selected[0U][0U] = 1U;
  ++selected.identity.configuration_epoch; ++selected.identity.revision;
  require(pending.select(selected,eligible) && eligible[0U] && !eligible[1U]);
  const auto preserve = eligible;
  ++selected.identity.publication;
  require(!pending.select(selected,eligible) && eligible == preserve);
  --selected.identity.publication; --selected.counts[0U];
  require(!pending.select(selected,eligible) && eligible == preserve);
  ++selected.counts[0U];
  const auto image = pending.checkpoint();
  require(installed.restore(image,device));
  const auto refuses = [&](auto corrupt) {
    auto changed = image; corrupt(changed);
    require(!installed.restore(changed,device));
    const auto retained = installed.checkpoint();
    require(retained.entries == image.entries && retained.attributes == image.attributes &&
        retained.candidates == image.candidates && retained.publication == image.publication && retained.device == image.device);
  };
  refuses([](auto &saved) { saved.entries[0U].advertisement.attributes_offset = 1U; });
  refuses([](auto &saved) { saved.attributes[1U] = 255U; });
  refuses([](auto &saved) { saved.attributes.push_back(0U); });
  refuses([](auto &saved) { saved.entries[0U].advertisement.down = true; });
  refuses([](auto &saved) { saved.entries[0U].advertisement.origin[6U] = 1U; });
  refuses([](auto &saved) { saved.candidates[0U][0U] = 1U; });
  refuses([](auto &saved) { saved.candidates[0U][0U] = 99U; });
  refuses([](auto &saved) { saved.budget.attributes += 1U; });
  require(!installed.restore(image,{2U,8U}));
  require(pending.begin(device,12U));
  attributes[8U] = 99U;
  require(pending.append(four,{0U,19U,0U},{0U,5U,9U},attributes).status == InterlevelTemplateStatus::applied);
  require(installed.attributes(0U)[2U] == 0x20U && installed.attributes(0U)[8U] == 7U);
  require(installed.entries()[0U].distance.metric == 17U && installed.select(selected,eligible));
  InterlevelTemplates tight({1U,14U,1U});
  require(tight.begin(device,1U));
  require(tight.append(four,{0U,17U,0U},{0U,5U,9U},attributes).status == InterlevelTemplateStatus::capacity);
  require(tight.entries().empty() && tight.attributes(0U).empty());
}
