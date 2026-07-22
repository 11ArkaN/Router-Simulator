// MLD listener tests exercise membership, randomized query response, v1
// compatibility, source filters and relative-deadline checkpoint restore.

#include "router/mld_listener.hpp"

#include "router/ip_address.hpp"

#include <array>
#include <chrono>
#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

router::packet::Ipv6 address(const char *text) {
  const auto parsed = router::ip::parse_ipv6(text);
  if (!parsed)
    throw std::runtime_error("MLD listener fixture address is invalid");
  return *parsed;
}

} // namespace

void mld_listener_tests() {
  using namespace router;
  using namespace router::lab;
  using namespace router::packet::mld;
  using Clock = MldListener::Clock;

  const auto start = Clock::time_point{std::chrono::seconds{100}};
  const auto group = address("ff02::1234");
  const auto source = address("2001:db8::10");
  MldListener listener{0x3810U};

  // ff02::1 is an implicit membership and RFC 2710 forbids Reports for it.
  require(listener.joined(packet::nd::all_nodes_multicast),
          "MLD listener omitted mandatory all-nodes membership");
  require(listener.join(packet::nd::all_nodes_multicast, start),
          "MLD listener rejected all-nodes membership");
  listener.set_link_state(true, false, start);
  std::array<MldListenerAction, device_catalog::mld_work_budget_actions>
      actions{};
  require(listener.poll(start, actions) == 0U,
          "MLD listener reported the all-nodes group");

  require(listener.join(group, start),
          "MLD listener rejected an any-source membership");
  require(listener.accepts(group, source),
          "MLD EXCLUDE empty filter rejected a source");
  const auto initial_count = listener.poll(start, actions);
  require(initial_count == 1U && !actions[0].version_one &&
              actions[0].record_type == RecordType::change_to_exclude &&
              actions[0].source_count == 0U,
          "MLDv2 join did not emit the required filter-mode change");

  // A valid link-local address triggers an RFC 3590 refresh. This is distinct
  // from the remaining robust state-change retransmission.
  listener.set_link_state(true, true, start + std::chrono::milliseconds{1});
  require(listener.poll(start + std::chrono::milliseconds{1}, actions) == 1U &&
              actions[0].record_type == RecordType::mode_is_exclude,
          "preferred link-local transition did not refresh MLD state");

  QueryView version_one_query{
      .source = address("fe80::1"),
      .destination = packet::nd::all_nodes_multicast,
      .multicast_address = {},
      .maximum_response_delay = std::chrono::seconds{10},
      .query_interval = device_catalog::mld_query_interval,
      .version_two = false};
  const auto query_time = start + std::chrono::seconds{1};
  listener.observe_query(version_one_query, query_time);
  require(listener.version_one_compatibility(),
          "MLDv1 Query did not enter compatibility mode");
  const auto response_deadline = listener.next_deadline();
  require(response_deadline && *response_deadline >= query_time &&
              *response_deadline <= query_time + std::chrono::seconds{10},
          "MLDv1 response delay escaped Max Response Delay");
  require(listener.poll(*response_deadline, actions) == 1U &&
              actions[0].version_one && !actions[0].done,
          "MLDv1 compatibility response used the wrong report form");

  const auto checkpoint_time = query_time + std::chrono::seconds{2};
  const auto checkpoint = listener.checkpoint(checkpoint_time);
  require(MldListener::validate_checkpoint(checkpoint),
          "MLD listener rejected its own checkpoint");
  MldListener restored{1U};
  const auto restore_time = Clock::time_point{std::chrono::seconds{500}};
  require(restored.restore(checkpoint, restore_time) &&
              restored.joined(group) && restored.accepts(group, source) &&
              restored.version_one_compatibility(),
          "MLD listener restore lost membership or compatibility state");

  auto invalid = checkpoint;
  invalid.random_state = 0U;
  const auto before = restored.checkpoint(restore_time);
  require(!restored.restore(invalid, restore_time) &&
              restored.checkpoint(restore_time).random_state ==
                  before.random_state,
          "invalid MLD checkpoint partially mutated live state");
}
