// Router-side MLD tests cover startup Queries, querier election, v1
// translation, source-filter forwarding, Last Listener probing and checkpoint
// continuity without a topology or direct listener reference.

#include "router/mld_router.hpp"

#include "router/ip_address.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <stdexcept>
#include <vector>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

router::packet::Ipv6 address(const char *text) {
  const auto parsed = router::ip::parse_ipv6(text);
  if (!parsed)
    throw std::runtime_error("MLD router fixture address is invalid");
  return *parsed;
}

router::packet::Ipv6 numbered(router::packet::Ipv6 value,
                              std::uint16_t number) {
  // Test identities are encoded in network byte order so all generated
  // addresses remain ordinary global unicast values and exercise the same
  // byte comparisons as decoded packets.
  value[14] = static_cast<std::uint8_t>(number >> 8U);
  value[15] = static_cast<std::uint8_t>(number);
  return value;
}

} // namespace

void mld_router_tests() {
  using namespace router;
  using namespace router::lab;
  using namespace router::packet::mld;
  using Clock = MldRouterInterface::Clock;

  const auto start = Clock::time_point{std::chrono::seconds{100}};
  const auto local = address("fe80::2");
  const auto group = address("ff3e::1234");
  const auto source_a = address("2001:db8::a");
  const auto source_b = address("2001:db8::b");
  const auto static_group = address("ff3e::9000");
  MldRouterInterface router;
  MldRouterConfiguration configuration;
  configuration.enabled = true;
  configuration.link_local_address = local;
  configuration.port_ordinal = 7U;
  require(router.configure(configuration, start),
          "MLD router rejected generated default configuration");
  require(router.configure_static_group(static_group) &&
              router.configure_static_source(static_group, source_a) &&
              !router.configure_static_starg(static_group) &&
              router.listener_accepts(static_group, source_a, start) &&
              !router.listener_accepts(static_group, source_b, start),
          "static (S,G) configuration violated source filtering");
  require(router.remove_static_source(static_group, source_a) &&
              router.configure_static_starg(static_group) &&
              router.listener_accepts(static_group, source_b, start),
          "static (*,G) configuration did not accept every source");

  std::array<MldRouterAction, device_catalog::mld_work_budget_actions>
      actions{};
  require(router.poll(start, actions) == 1U && router.querier() &&
              actions[0].kind == MldRouterQueryKind::general &&
              !actions[0].version_one &&
              actions[0].maximum_response_delay ==
                  device_catalog::mld_query_response_interval,
          "MLD router did not emit its immediate startup General Query");
  router.count_receive(MldReceiveStatistic::query);
  router.count_receive(MldReceiveStatistic::report_v1);
  router.count_receive(MldReceiveStatistic::bad_checksum);
  require(router.statistics().queries_transmitted == 1U &&
              router.statistics().queries_received == 1U &&
              router.statistics().reports_v1_received == 1U &&
              router.statistics().bad_checksum == 1U,
          "MLD interface owner did not retain wire statistics");

  const std::array<packet::Ipv6, 1U> include_sources{source_a};
  const RecordView include{.multicast_address = group,
                           .source_count = 1U,
                           .type = RecordType::mode_is_include};
  require(router.observe_record(include, include_sources, start) &&
              router.listener_accepts(group, source_a, start) &&
              !router.listener_accepts(group, source_b, start),
          "MLD INCLUDE source filter produced the wrong forwarding suggestion");

  const RecordView block{.multicast_address = group,
                         .source_count = 1U,
                         .type = RecordType::block_old_sources};
  require(router.observe_record(block, include_sources, start) &&
              router.poll(start, actions) == 1U &&
              actions[0].kind ==
                  MldRouterQueryKind::multicast_address_and_sources &&
              actions[0].source_count == 1U &&
              actions[0].sources[0] == source_a,
          "MLD BLOCK did not start a source-specific Last Listener Query");

  // A lower link-local IID wins election. The validated Query carries the
  // sender's timer parameters, which determine the other-querier timeout.
  QueryView lower_query{.source = address("fe80::1"),
                        .destination = packet::nd::all_nodes_multicast,
                        .multicast_address = {},
                        .maximum_response_delay = std::chrono::seconds{10},
                        .query_interval = std::chrono::seconds{125},
                        .robustness_variable = 2U,
                        .version_two = false};
  router.observe_query(lower_query, {}, start + std::chrono::milliseconds{1});
  require(!router.querier() && router.querier_address() == lower_query.source &&
              router.operational_version() == 1U,
          "MLD querier election or older-version compatibility was incorrect");

  const auto checkpoint_time = start + std::chrono::seconds{1};
  const auto checkpoint = router.checkpoint(checkpoint_time);
  require(MldRouterInterface::validate_checkpoint(checkpoint),
          "MLD router rejected its own checkpoint");
  MldRouterInterface restored;
  const auto restore_time = Clock::time_point{std::chrono::seconds{500}};
  require(restored.restore(checkpoint, restore_time) &&
              restored.group_count() == 1U && !restored.querier() &&
              restored.static_group_count() == 1U &&
              restored.listener_accepts(static_group, source_b, restore_time) &&
              restored.querier_address() == lower_query.source &&
              restored.operational_version() == 1U &&
              restored.listener_accepts(group, source_a, restore_time),
          "MLD router restore lost filter or election state");
  require(restored.statistics().queries_transmitted ==
                  checkpoint.statistics.queries_transmitted &&
              restored.statistics().queries_received ==
                  checkpoint.statistics.queries_received &&
              restored.statistics().reports_v1_received ==
                  checkpoint.statistics.reports_v1_received &&
              restored.statistics().bad_checksum ==
                  checkpoint.statistics.bad_checksum,
          "MLD checkpoint lost interface statistics");
  restored.clear_statistics();
  require(restored.statistics().queries_transmitted == 0U &&
              restored.statistics().bad_checksum == 0U &&
              restored.group_count() == 1U,
          "MLD statistics clear changed listener state or retained counters");
  restored.clear_older_host_compatibility();
  require(restored.operational_version() == 2U &&
              restored.querier_address() == lower_query.source,
          "MLD version clear changed querier election or retained v1 mode");
  restored.clear_database();
  require(restored.group_count() == 0U && restored.static_group_count() == 1U &&
              restored.listener_accepts(static_group, source_b, restore_time),
          "dynamic database clear erased static MLD configuration");

  // RFC 3590 requires routers to discard an unspecified-source v1 Report.
  VersionOneView invalid_v1{.source = {},
                            .destination = group,
                            .multicast_address = group,
                            .type = version_one_report_type};
  require(!restored.observe_version_one(invalid_v1, restore_time),
          "MLD router accepted an unspecified-source Report");

  MldRouterInterface version_one_router;
  configuration.version = 1U;
  require(version_one_router.configure(configuration, start),
          "MLDv1 router configuration was rejected");
  require(version_one_router.poll(start, actions) == 1U &&
              actions[0].version_one,
          "configured MLDv1 router emitted an MLDv2 General Query");
  VersionOneView report{.source = address("fe80::10"),
                        .destination = group,
                        .multicast_address = group,
                        .type = version_one_report_type};
  require(version_one_router.observe_version_one(report, start) &&
              version_one_router.listener_accepts(group, source_b, start),
          "MLDv1 Report was not translated to EXCLUDE empty state");
  version_one_router.clear_older_host_compatibility();
  const auto cleared_version = version_one_router.checkpoint(start);
  require(cleared_version.groups.size() == 1U &&
              !cleared_version.groups[0].older_host_present &&
              version_one_router.listener_accepts(group, source_b, start),
          "MLD version clear erased listener state or retained compatibility");
  version_one_router.clear_database(group);
  require(version_one_router.group_count() == 0U,
          "group-specific MLD database clear retained the selected group");
  require(version_one_router.observe_version_one(report, start) &&
              version_one_router.group_count() == 1U,
          "MLD database could not learn again after a clear");
  version_one_router.clear_database();
  require(version_one_router.group_count() == 0U,
          "interface-wide MLD database clear retained dynamic groups");

  // SR OS treats all three maximum-number leaves as admission controls. A
  // lower value applies only to state learned after the configuration change;
  // deleting memberships merely to make the database fit would create a
  // forwarding outage that the documented command semantics do not permit.
  MldRouterInterface group_limited;
  auto limited_configuration = configuration;
  limited_configuration.version = 2U;
  limited_configuration.maximum_number_groups = 2U;
  require(group_limited.configure(limited_configuration, start),
          "MLD maximum group configuration was rejected");
  const auto second_group = address("ff3e::1235");
  const auto third_group = address("ff3e::1236");
  require(
      group_limited.observe_record(include, include_sources, start) &&
          group_limited.observe_record({.multicast_address = second_group,
                                        .source_count = 1U,
                                        .type = RecordType::mode_is_include},
                                       include_sources, start) &&
          group_limited.group_count() == 2U,
      "MLD group admission limit rejected state below its ceiling");
  limited_configuration.maximum_number_groups = 1U;
  require(
      group_limited.configure(limited_configuration, start) &&
          group_limited.group_count() == 2U &&
          group_limited.observe_record(include, include_sources, start) &&
          !group_limited.observe_record({.multicast_address = third_group,
                                         .source_count = 1U,
                                         .type = RecordType::mode_is_include},
                                        include_sources, start) &&
          group_limited.group_count() == 2U,
      "lowering the MLD group limit deleted or admitted the wrong state");

  // Existing (S,G) records remain refreshable at the ceiling. Otherwise the
  // same listener Report that created a record could no longer keep its timer
  // alive once the interface reached its configured limit.
  MldRouterInterface source_limited;
  limited_configuration.maximum_number_groups = 0U;
  limited_configuration.maximum_number_sources = 1U;
  limited_configuration.maximum_number_group_sources = 0U;
  require(source_limited.configure(limited_configuration, start) &&
              source_limited.observe_record(include, include_sources, start),
          "MLD per-group source limit rejected its first source");
  const std::array<packet::Ipv6, 2U> two_sources{source_a, source_b};
  require(source_limited.observe_record({.multicast_address = group,
                                         .source_count = 2U,
                                         .type = RecordType::mode_is_include},
                                        two_sources,
                                        start + std::chrono::seconds{1}) &&
              source_limited.group_source_count() == 1U &&
              source_limited.listener_accepts(
                  group, source_a, start + std::chrono::seconds{1}) &&
              !source_limited.listener_accepts(group, source_b,
                                               start + std::chrono::seconds{1}),
          "MLD per-group source limit blocked refresh or admitted overflow");

  // maximum-number-group-sources is shared by every dynamic group on one
  // interface. The second group may exist in INCLUDE empty state, but its new
  // source pair must not consume state beyond the interface-wide ceiling.
  MldRouterInterface interface_source_limited;
  limited_configuration.maximum_number_sources = 0U;
  limited_configuration.maximum_number_group_sources = 1U;
  require(interface_source_limited.configure(limited_configuration, start) &&
              interface_source_limited.observe_record(include, include_sources,
                                                      start) &&
              interface_source_limited.observe_record(
                  {.multicast_address = second_group,
                   .source_count = 1U,
                   .type = RecordType::mode_is_include},
                  std::array<packet::Ipv6, 1U>{source_b}, start) &&
              interface_source_limited.group_count() == 2U &&
              interface_source_limited.group_source_count() == 1U &&
              !interface_source_limited.listener_accepts(second_group, source_b,
                                                         start),
          "MLD interface source limit admitted an extra (S,G) record");

  const auto limited_checkpoint =
      interface_source_limited.checkpoint(checkpoint_time);
  MldRouterInterface limited_restored;
  require(limited_restored.restore(limited_checkpoint, restore_time) &&
              limited_restored.configuration().maximum_number_group_sources ==
                  1U &&
              limited_restored.group_count() == 2U &&
              limited_restored.group_source_count() == 1U,
          "MLD checkpoint lost configured admission limits or learned state");

  // Router database scale is deliberately separate from the bounded source
  // list carried by one decoded Report. Multiple legal wire messages must be
  // able to build the full SR OS per-group limit instead of stopping at the
  // former 64-entry packet-work capacity.
  MldRouterInterface scaled_router;
  limited_configuration.maximum_number_group_sources = 32000U;
  limited_configuration.maximum_number_sources = 1000U;
  require(scaled_router.configure(limited_configuration, start),
          "MLD full-range source configuration was rejected");
  const auto source_base = address("2001:db8:100::");
  std::vector<packet::Ipv6> source_batch;
  source_batch.reserve(device_catalog::mld_sources_per_group);
  for (std::uint16_t first = 1U; first <= 1000U;
       first = static_cast<std::uint16_t>(
           first + device_catalog::mld_sources_per_group)) {
    source_batch.clear();
    const auto end = static_cast<std::uint16_t>(std::min<std::size_t>(
        1000U, first + device_catalog::mld_sources_per_group - 1U));
    for (auto value = first; value <= end; ++value)
      source_batch.push_back(numbered(source_base, value));
    require(
        scaled_router.observe_record(
            {.multicast_address = group,
             .source_count = static_cast<std::uint16_t>(source_batch.size()),
             .type = RecordType::mode_is_include},
            source_batch, start),
        "MLD could not accumulate a legal source batch");
  }
  const std::array<packet::Ipv6, 1U> overflow_source{
      numbered(source_base, 1001U)};
  require(
      scaled_router.group_source_count() == 1000U &&
          scaled_router.observe_record({.multicast_address = group,
                                        .source_count = 1U,
                                        .type = RecordType::mode_is_include},
                                       overflow_source, start) &&
          scaled_router.group_source_count() == 1000U &&
          !scaled_router.listener_accepts(group, overflow_source[0], start),
      "MLD full per-group limit admitted overflow or retained a 64-entry cap");

  // The group repository is also dynamic. Crossing 64 groups proves that the
  // packet-work budget does not double as a hidden router scale ceiling.
  MldRouterInterface scaled_groups;
  limited_configuration.maximum_number_sources = 0U;
  require(scaled_groups.configure(limited_configuration, start),
          "MLD full-range group configuration was rejected");
  const auto group_base = address("ff3e::");
  for (std::uint16_t index = 1U; index <= 65U; ++index)
    require(scaled_groups.observe_record(
                {.multicast_address = numbered(group_base, index),
                 .source_count = 1U,
                 .type = RecordType::mode_is_include},
                include_sources, start),
            "MLD router retained the old 64-group resource ceiling");
  require(scaled_groups.group_count() == 65U,
          "MLD router did not retain every accepted group above 64 entries");

  auto invalid_checkpoint = checkpoint;
  invalid_checkpoint.groups[0].sources[0].address =
      packet::nd::all_nodes_multicast;
  const auto before = restored.checkpoint(restore_time);
  require(!restored.restore(invalid_checkpoint, restore_time) &&
              restored.checkpoint(restore_time).groups.size() ==
                  before.groups.size(),
          "invalid MLD router checkpoint partially mutated live state");
}
