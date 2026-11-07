// Stable packing tests preserve old placement and caller output on refusal.
// Inputs are local semantic units; no wire exchange or mutable protocol owner.
#include "router/isis_fragment_plan.hpp"
#include <array>
#include <source_location>
#include <stdexcept>
#include <string>
namespace {
void require(bool value, std::source_location where = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS fragment plan invariant at " + std::to_string(where.line()));
}
}
void isis_fragment_plan_tests() {
  using namespace router::isis;
  FragmentPlanner planner(4U);
  const std::array<std::uint8_t, 4U> option{250U, 2U, 1U, 2U};
  const std::array<std::uint8_t, 4U> area{1U, 2U, 1U, 0x49U};
  std::array units{FragmentUnit{1U, option, {}, false}, FragmentUnit{2U, option, std::uint8_t{0U}, false},
      FragmentUnit{3U, option, std::uint8_t{1U}, false}, FragmentUnit{4U, area, {}, true}};
  std::array<std::uint8_t, 4U> output{99U, 99U, 99U, 99U};
  require(planner.plan(units, 8U, 2U, false, output) == FragmentPlanStatus::planned &&
      output == std::array<std::uint8_t, 4U>{1U, 0U, 1U, 0U});
  std::array<std::uint8_t, 8U> first{}, second{};
  std::array fragments{FragmentOptions{first, 7U}, FragmentOptions{second, 6U}};
  require(planner.compose(units, 8U, false, fragments) == FragmentPlanStatus::planned &&
      fragments[0U].size == 8U && fragments[1U].size == 8U &&
      first == std::array<std::uint8_t, 8U>{250U, 2U, 1U, 2U, 1U, 2U, 1U, 0x49U} &&
      second == std::array<std::uint8_t, 8U>{250U, 2U, 1U, 2U, 250U, 2U, 1U, 2U});
  const auto old_first = first, old_second = second;
  fragments[1U].storage = std::span{second}.first(7U);
  require(planner.compose(units, 8U, false, fragments) == FragmentPlanStatus::capacity &&
      first == old_first && second == old_second && fragments[0U].size == 8U && fragments[1U].size == 8U);
  const auto before = output;
  require(planner.plan(units, 7U, 2U, false, output) == FragmentPlanStatus::capacity && output == before);
  require(planner.plan(units, 8U, 2U, true, output) == FragmentPlanStatus::malformed && output == before);
  units[3U].root_only = false;
  require(planner.plan(units, 8U, 2U, false, output) == FragmentPlanStatus::malformed && output == before);
  units[3U].tlv = option;
  units[3U].previous_fragment = std::uint8_t{255U};
  require(planner.plan(units, 4U, 256U, false, output) == FragmentPlanStatus::planned &&
      output == std::array<std::uint8_t, 4U>{2U, 0U, 1U, 255U});
  require(planner.plan(units, 4U, 257U, false, output) == FragmentPlanStatus::malformed);
  units[1U].identity = units[0U].identity;
  require(planner.plan(units, 4U, 256U, false, output) == FragmentPlanStatus::malformed);
  const std::array<std::uint8_t, 2U> auth{10U, 0U};
  const std::array bad{FragmentUnit{1U, auth, {}, false}};
  require(planner.plan(bad, 8U, 1U, false, output) == FragmentPlanStatus::malformed);
  require(planner.plan({}, 0U, 1U, false, {}) == FragmentPlanStatus::planned);
  FragmentPlanner empty(0U);
  require(empty.plan(bad, 8U, 1U, false, output) == FragmentPlanStatus::capacity);
  const std::array<std::uint8_t, 8U> paired{250U, 2U, 1U, 2U, 251U, 2U, 3U, 4U};
  const std::array pair{FragmentUnit{FragmentUnitId{9U, 1U}, paired, {}, false}};
  require(planner.plan(pair, 7U, 2U, false, output) == FragmentPlanStatus::capacity);
  require(planner.plan(pair, 8U, 2U, false, output) == FragmentPlanStatus::planned && !output[0U]);
  const std::array domains{FragmentUnit{FragmentUnitId{0U, 99U}, option, {}, false},
      FragmentUnit{FragmentUnitId{1U, 1U}, option, {}, false}};
  require(planner.plan(domains, 8U, 1U, false, output) == FragmentPlanStatus::planned);

  const std::array<std::uint8_t, 7U> larger{250U, 5U, 1U, 2U, 3U, 4U, 5U};
  const std::array relocate{FragmentUnit{1U, option, std::uint8_t{0U}, false},
      FragmentUnit{2U, option, std::uint8_t{1U}, false}, FragmentUnit{3U, larger, {}, false}};
  require(planner.plan(relocate, 10U, 2U, false, output) == FragmentPlanStatus::planned &&
      output[0U] == 1U && output[1U] == 1U && output[2U] == 0U);

}
