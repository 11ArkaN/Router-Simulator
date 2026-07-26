// MLDv2 router state tables from RFC 3810 sections 7.3 through 7.6, including
// MLDv1 host compatibility. Protocol work is bounded by generated group,
// source and action capacities and all deadlines use steady_clock.

#include "router/mld_router.hpp"

#include "router/ip_address.hpp"

#include <algorithm>
#include <limits>

namespace router::lab {
namespace {

using Clock = MldRouterInterface::Clock;
constexpr auto no_deadline = Clock::time_point::max();

bool valid_configuration(const MldRouterConfiguration &value) noexcept {
  return (!value.enabled || ip::is_link_local(value.link_local_address)) &&
         value.query_interval >=
             std::chrono::seconds{
                 device_catalog::mld_minimum_query_interval_seconds} &&
         value.query_interval <=
             std::chrono::seconds{
                 device_catalog::mld_maximum_query_interval_seconds} &&
         value.query_response_interval >=
             std::chrono::seconds{
                 device_catalog::mld_minimum_query_response_interval_seconds} &&
         value.query_response_interval <=
             std::chrono::seconds{
                 device_catalog::mld_maximum_query_response_interval_seconds} &&
         value.query_response_interval < value.query_interval &&
         value.last_listener_query_interval >=
             std::chrono::seconds{
                 device_catalog::
                     mld_minimum_last_listener_query_interval_seconds} &&
         value.last_listener_query_interval <=
             std::chrono::seconds{
                 device_catalog::
                     mld_maximum_last_listener_query_interval_seconds} &&
         value.robustness_variable >=
             device_catalog::mld_minimum_robustness_variable &&
         value.robustness_variable <=
             device_catalog::mld_maximum_robustness_variable &&
         value.version >= device_catalog::mld_minimum_version &&
         value.version <= device_catalog::mld_maximum_version &&
         value.maximum_number_groups <=
             device_catalog::mld_maximum_number_groups &&
         value.maximum_number_group_sources <=
             device_catalog::mld_maximum_number_group_sources &&
         value.maximum_number_sources <=
             device_catalog::mld_maximum_number_sources;
}

bool valid_source(const packet::Ipv6 &value) noexcept {
  return !ip::is_unspecified(value) && !ip::is_multicast(value);
}

bool lower_querier(const packet::Ipv6 &candidate,
                   const packet::Ipv6 &local) noexcept {
  // RFC 3810 compares the last 64 bits because every valid Query source uses
  // FE80::/64. A lexicographic byte comparison is identical to unsigned
  // big-endian integer ordering and avoids host-endian conversions.
  return std::lexicographical_compare(candidate.begin() + 8, candidate.end(),
                                      local.begin() + 8, local.end());
}

template <typename Item>
bool contains_address(const std::vector<Item> &values,
                      const packet::Ipv6 &address) {
  return std::any_of(values.begin(), values.end(), [&](const auto &value) {
    if constexpr (requires { value.address; })
      return value.address == address;
    else
      return value == address;
  });
}

template <typename Predicate>
std::vector<packet::Ipv6> select_sources(const std::vector<packet::Ipv6> &left,
                                         const std::vector<packet::Ipv6> &right,
                                         Predicate predicate) {
  std::vector<packet::Ipv6> result;
  result.reserve(left.size());
  for (const auto &address : left) {
    const bool present =
        std::find(right.begin(), right.end(), address) != right.end();
    if (predicate(present) && !contains_address(result, address))
      result.push_back(address);
  }
  return result;
}

std::vector<packet::Ipv6>
set_union_bounded(const std::vector<packet::Ipv6> &left,
                  const std::vector<packet::Ipv6> &right) {
  auto result = left;
  result.reserve(std::min(device_catalog::mld_router_sources_per_group,
                          left.size() + right.size()));
  for (const auto &address : right)
    if (!contains_address(result, address))
      result.push_back(address);
  return result;
}

std::vector<packet::Ipv6>
set_intersection(const std::vector<packet::Ipv6> &left,
                 const std::vector<packet::Ipv6> &right) {
  return select_sources(left, right, [](bool present) { return present; });
}

std::vector<packet::Ipv6>
set_difference(const std::vector<packet::Ipv6> &left,
               const std::vector<packet::Ipv6> &right) {
  return select_sources(left, right, [](bool present) { return !present; });
}

std::int64_t relative(Clock::time_point deadline, Clock::time_point now) {
  if (deadline == no_deadline)
    return 0;
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             deadline > now ? deadline - now : Clock::duration::zero())
      .count();
}

} // namespace

MldRouterInterface::MldRouterInterface() {
  // The official scale ranges are admission ceilings, not mandatory startup
  // allocations. Leaving these vectors empty makes an idle MLD interface
  // cheap while geometric growth still keeps accepted entries contiguous.
  // Reserving 16000 full group records per port would penalize every small
  // laboratory and tie configured scale to the initial memory image.
}

void MldRouterInterface::count_receive(MldReceiveStatistic statistic) noexcept {
  // Saturating counters are not used by SR OS show output. Unsigned wrap is
  // well-defined and matches fixed-width hardware-style counters after an
  // astronomically long run, while a conditional on every MLD packet would
  // add work without improving observable behavior at realistic rates.
  switch (statistic) {
  case MldReceiveStatistic::query:
    ++statistics_.queries_received;
    break;
  case MldReceiveStatistic::report_v1:
    ++statistics_.reports_v1_received;
    break;
  case MldReceiveStatistic::report_v2:
    ++statistics_.reports_v2_received;
    break;
  case MldReceiveStatistic::done:
    ++statistics_.dones_received;
    break;
  case MldReceiveStatistic::bad_length:
    ++statistics_.bad_length;
    break;
  case MldReceiveStatistic::bad_checksum:
    ++statistics_.bad_checksum;
    break;
  case MldReceiveStatistic::unknown_type:
    ++statistics_.unknown_type;
    break;
  case MldReceiveStatistic::bad_receive_interface:
    ++statistics_.bad_receive_interface;
    break;
  case MldReceiveStatistic::non_local:
    ++statistics_.receive_non_local;
    break;
  case MldReceiveStatistic::wrong_version:
    ++statistics_.receive_wrong_version;
    break;
  case MldReceiveStatistic::policy_drop:
    ++statistics_.policy_drops;
    break;
  case MldReceiveStatistic::no_router_alert:
    ++statistics_.no_router_alert;
    break;
  case MldReceiveStatistic::bad_encoding:
    ++statistics_.receive_bad_encodings;
    break;
  case MldReceiveStatistic::packet_drop:
    ++statistics_.receive_packet_drops;
    break;
  case MldReceiveStatistic::local_scope:
    ++statistics_.local_scope_packets;
    break;
  case MldReceiveStatistic::reserved_scope:
    ++statistics_.reserved_scope_packets;
    break;
  case MldReceiveStatistic::mcac_policy_drop:
    ++statistics_.mcac_policy_drops;
    break;
  }
}

bool MldRouterInterface::configure(const MldRouterConfiguration &configuration,
                                   Clock::time_point now) noexcept {
  if (!valid_configuration(configuration))
    return false;
  const bool new_generation =
      !configuration_.enabled ||
      configuration_.port_ordinal != configuration.port_ordinal ||
      configuration_.link_local_address != configuration.link_local_address;
  configuration_ = configuration;
  if (!configuration.enabled) {
    groups_.clear();
    querier_ = false;
    other_querier_timer_running_ = false;
    general_query_deadline_ = no_deadline;
    other_querier_deadline_ = no_deadline;
    older_querier_deadline_ = no_deadline;
    querier_address_ = {};
    startup_queries_remaining_ = 0U;
    older_querier_present_ = false;
    return true;
  }
  if (new_generation) {
    groups_.clear();
    querier_ = true;
    other_querier_timer_running_ = false;
    other_querier_deadline_ = no_deadline;
    older_querier_deadline_ = no_deadline;
    querier_address_ = configuration.link_local_address;
    startup_queries_remaining_ = configuration.robustness_variable;
    general_query_deadline_ = now;
    older_querier_present_ = false;
  }
  return true;
}

MldRouterInterface::Group *
MldRouterInterface::find(const packet::Ipv6 &group) noexcept {
  const auto found =
      std::find_if(groups_.begin(), groups_.end(), [&](const auto &entry) {
        return entry.multicast_address == group;
      });
  return found == groups_.end() ? nullptr : &*found;
}

MldRouterInterface::StaticGroup *
MldRouterInterface::find_static(const packet::Ipv6 &group) noexcept {
  const auto found = std::find_if(
      static_groups_.begin(), static_groups_.end(),
      [&](const auto &entry) { return entry.multicast_address == group; });
  return found == static_groups_.end() ? nullptr : &*found;
}

const MldRouterInterface::StaticGroup *
MldRouterInterface::find_static(const packet::Ipv6 &group) const noexcept {
  const auto found = std::find_if(
      static_groups_.begin(), static_groups_.end(),
      [&](const auto &entry) { return entry.multicast_address == group; });
  return found == static_groups_.end() ? nullptr : &*found;
}

bool MldRouterInterface::configure_static_group(
    const packet::Ipv6 &group) noexcept {
  if (!ip::is_multicast(group))
    return false;
  if (find_static(group))
    return true;
  if (static_groups_.size() == device_catalog::mld_router_groups_per_interface)
    return false;
  static_groups_.push_back(
      {.multicast_address = group, .sources = {}, .starg = false});
  // Static source storage grows only for sources the operator configures.
  return true;
}

bool MldRouterInterface::configure_static_starg(
    const packet::Ipv6 &group) noexcept {
  auto *entry = find_static(group);
  if (!entry || !entry->sources.empty())
    return false;
  entry->starg = true;
  return true;
}

bool MldRouterInterface::configure_static_source(
    const packet::Ipv6 &group, const packet::Ipv6 &source) noexcept {
  auto *entry = find_static(group);
  if (!entry || entry->starg || !valid_source(source))
    return false;
  if (contains_address(entry->sources, source))
    return true;
  if (entry->sources.size() == device_catalog::mld_router_sources_per_group)
    return false;
  entry->sources.push_back(source);
  return true;
}

bool MldRouterInterface::remove_static_group(
    const packet::Ipv6 &group) noexcept {
  const auto before = static_groups_.size();
  std::erase_if(static_groups_, [&](const auto &entry) {
    return entry.multicast_address == group;
  });
  return static_groups_.size() != before;
}

bool MldRouterInterface::remove_static_starg(
    const packet::Ipv6 &group) noexcept {
  auto *entry = find_static(group);
  if (!entry || !entry->starg)
    return false;
  entry->starg = false;
  return true;
}

bool MldRouterInterface::remove_static_source(
    const packet::Ipv6 &group, const packet::Ipv6 &source) noexcept {
  auto *entry = find_static(group);
  if (!entry)
    return false;
  const auto before = entry->sources.size();
  std::erase(entry->sources, source);
  return entry->sources.size() != before;
}

const MldRouterInterface::Group *
MldRouterInterface::find(const packet::Ipv6 &group) const noexcept {
  const auto found =
      std::find_if(groups_.begin(), groups_.end(), [&](const auto &entry) {
        return entry.multicast_address == group;
      });
  return found == groups_.end() ? nullptr : &*found;
}

MldRouterInterface::Group *
MldRouterInterface::ensure(const packet::Ipv6 &group) noexcept {
  if (auto *entry = find(group))
    return entry;
  if (!ip::is_multicast(group) ||
      (configuration_.maximum_number_groups &&
       groups_.size() >= configuration_.maximum_number_groups) ||
      groups_.size() == device_catalog::mld_router_groups_per_interface)
    return nullptr;
  groups_.emplace_back();
  auto &result = groups_.back();
  result.multicast_address = group;
  // Dynamic source state is demand allocated. Pending wire actions remain
  // bounded separately because one encoded Query cannot exceed its packet
  // source-list capacity.
  for (auto &pending : result.pending_queries)
    pending.sources.reserve(device_catalog::mld_sources_per_group);
  return &result;
}

std::size_t MldRouterInterface::group_source_count() const noexcept {
  // SR OS maximum-number-group-sources counts (S,G) records across the whole
  // interface. EXCLUDE-list entries are still receiver information for one
  // group and source pair, so both timer states contribute to this count.
  std::size_t result{};
  for (const auto &group : groups_)
    result += group.sources.size();
  return result;
}

MldRouterInterface::Clock::duration
MldRouterInterface::multicast_address_listening_interval() const {
  return configuration_.query_interval * configuration_.robustness_variable +
         configuration_.query_response_interval;
}

MldRouterInterface::Clock::duration
MldRouterInterface::last_listener_query_time() const {
  return configuration_.last_listener_query_interval *
         configuration_.robustness_variable;
}

void MldRouterInterface::observe_query(const packet::mld::QueryView &query,
                                       std::span<const packet::Ipv6> sources,
                                       Clock::time_point now) noexcept {
  if (!configuration_.enabled)
    return;
  if (!query.version_two) {
    // RFC 3810 section 8.3.1 requires v2 routers to remain in v1 querier
    // compatibility for Robustness * Query Interval + Query Response
    // Interval after an older Query. This timer is interface-wide and is
    // distinct from the per-group older-host timer learned from Reports.
    older_querier_present_ = true;
    older_querier_deadline_ =
        now +
        query.query_interval * (query.robustness_variable
                                    ? query.robustness_variable
                                    : configuration_.robustness_variable) +
        query.maximum_response_delay;
  }
  if (lower_querier(query.source, configuration_.link_local_address)) {
    const auto robustness = query.robustness_variable
                                ? query.robustness_variable
                                : configuration_.robustness_variable;
    const auto interval = query.query_interval.count()
                              ? query.query_interval
                              : device_catalog::mld_query_interval;
    querier_ = false;
    other_querier_timer_running_ = true;
    other_querier_deadline_ =
        now + interval * robustness + query.maximum_response_delay / 2;
    querier_address_ = query.source;
  }
  if (query.suppress_router_processing ||
      ip::is_unspecified(query.multicast_address))
    return;
  auto *group = find(query.multicast_address);
  if (!group)
    return;
  const auto lowered = now + last_listener_query_time();
  if (!query.source_count) {
    if (group->filter_timer_running && group->filter_deadline > lowered)
      group->filter_deadline = lowered;
    return;
  }
  if (sources.size() != query.source_count ||
      sources.size() > device_catalog::mld_sources_per_group)
    return;
  for (auto &state : group->sources)
    if (std::find(sources.begin(), sources.end(), state.address) !=
            sources.end() &&
        state.timer_running && state.expires > lowered)
      state.expires = lowered;
}

void MldRouterInterface::schedule_query(Group &group,
                                        bool multicast_address_query,
                                        std::span<const packet::Ipv6> sources,
                                        Clock::time_point now) noexcept {
  if (!querier_ || sources.size() > device_catalog::mld_sources_per_group)
    return;
  auto slot = std::find_if(group.pending_queries.begin(),
                           group.pending_queries.end(), [&](const auto &entry) {
                             return entry.transmissions_remaining &&
                                    entry.multicast_address_query ==
                                        multicast_address_query;
                           });
  if (slot == group.pending_queries.end())
    slot = std::find_if(
        group.pending_queries.begin(), group.pending_queries.end(),
        [](const auto &entry) { return !entry.transmissions_remaining; });
  if (slot == group.pending_queries.end())
    return;
  slot->multicast_address_query = multicast_address_query;
  if (!multicast_address_query) {
    for (const auto &source : sources)
      if (!contains_address(slot->sources, source) &&
          slot->sources.size() < device_catalog::mld_sources_per_group)
        slot->sources.push_back(source);
  } else {
    slot->sources.clear();
  }
  slot->transmissions_remaining = configuration_.robustness_variable;
  slot->deadline = now;

  const auto lower_to = now + last_listener_query_time();
  if (multicast_address_query) {
    if (group.filter_timer_running && group.filter_deadline > lower_to)
      group.filter_deadline = lower_to;
  } else {
    for (auto &state : group.sources)
      if (contains_address(slot->sources, state.address) &&
          state.timer_running && state.expires > lower_to)
        state.expires = lower_to;
  }
}

bool MldRouterInterface::observe_version_one(
    const packet::mld::VersionOneView &message,
    Clock::time_point now) noexcept {
  if (!configuration_.enabled || ip::is_unspecified(message.source))
    return false;
  auto *group = ensure(message.multicast_address);
  if (!group)
    return false;
  group->older_host_present = true;
  group->older_host_deadline = now + multicast_address_listening_interval();
  if (message.type == packet::mld::version_one_report_type) {
    // RFC 3810 section 8.3.2 translates a v1 Report to IS_EX({}).
    group->mode = MldFilterMode::exclude;
    group->sources.clear();
    group->filter_timer_running = true;
    group->filter_deadline = now + multicast_address_listening_interval();
  } else {
    // A v1 Done is TO_IN({}). The group remains forwarding until the Last
    // Listener Query Time expires or another listener refreshes it.
    schedule_query(*group, true, {}, now);
  }
  return true;
}

bool MldRouterInterface::observe_translated_version_one_report(
    const packet::mld::VersionOneView &message,
    std::span<const packet::Ipv6> translated_sources,
    Clock::time_point now) noexcept {
  if (message.type != packet::mld::version_one_report_type ||
      translated_sources.empty())
    return false;

  // Nokia defines SSM translation as replacing the received (*,G) with one
  // (S,G) for every configured source. MODE_IS_INCLUDE is the RFC 3810 state
  // representation of that source set. The synthetic view carries no frame
  // offsets because observe_record consumes only its type and group address.
  const packet::mld::RecordView translated{
      .multicast_address = message.multicast_address,
      .source_count = static_cast<std::uint16_t>(translated_sources.size()),
      .type = packet::mld::RecordType::mode_is_include};
  if (!observe_record(translated, translated_sources, now))
    return false;

  // A translated listener is still an MLDv1 listener. Retaining the older-host
  // timer prevents v2 state-change processing from prematurely pruning it.
  auto *group = find(message.multicast_address);
  if (!group)
    return false;
  group->older_host_present = true;
  group->older_host_deadline = now + multicast_address_listening_interval();
  return true;
}

bool MldRouterInterface::observe_record(
    const packet::mld::RecordView &record,
    std::span<const packet::Ipv6> report_sources,
    Clock::time_point now) noexcept {
  if (!configuration_.enabled ||
      report_sources.size() > device_catalog::mld_router_sources_per_group ||
      std::any_of(report_sources.begin(), report_sources.end(),
                  [](const auto &source) { return !valid_source(source); }))
    return false;
  const bool created_group = find(record.multicast_address) == nullptr;
  auto *group = ensure(record.multicast_address);
  if (!group)
    return false;

  std::vector<packet::Ipv6> incoming;
  incoming.reserve(report_sources.size());
  const auto existing_interface_sources = group_source_count();
  std::size_t accepted_new_sources{};
  for (const auto &source : report_sources) {
    if (contains_address(incoming, source))
      continue;
    const bool already_accepted = contains_address(group->sources, source);
    const bool group_limit_reached =
        !already_accepted && configuration_.maximum_number_sources &&
        group->sources.size() + accepted_new_sources >=
            configuration_.maximum_number_sources;
    const bool interface_limit_reached =
        !already_accepted && configuration_.maximum_number_group_sources &&
        existing_interface_sources + accepted_new_sources >=
            configuration_.maximum_number_group_sources;
    // Lowering a configured limit never deletes existing receiver state.
    // Only a previously unseen (S,G) is omitted, matching the Nokia command
    // semantics while allowing the rest of one Report to refresh timers.
    if (!group_limit_reached && !interface_limit_reached) {
      incoming.push_back(source);
      accepted_new_sources += !already_accepted ? 1U : 0U;
    }
  }
  // Resource exhaustion is distinct from an operator limit. It rejects the
  // complete Report atomically instead of silently pretending that selected
  // source pairs were learned. The ceiling covers the full configurable
  // maximum and is generated with the release profile.
  if (existing_interface_sources + accepted_new_sources >
      device_catalog::mld_router_group_sources_per_interface) {
    // ensure() appends a new group at the end. Admission failure must not
    // leave that empty shell visible in show output or consume a group slot.
    // Existing groups are never removed by a rejected Report.
    if (created_group)
      groups_.pop_back();
    return false;
  }
  if (group->older_host_present &&
      record.type == packet::mld::RecordType::change_to_exclude)
    incoming.clear();
  std::vector<packet::Ipv6> requested;
  std::vector<packet::Ipv6> excluded;
  requested.reserve(group->sources.size() + incoming.size());
  excluded.reserve(group->sources.size());
  for (const auto &source : group->sources) {
    if (source.timer_running && source.expires > now)
      requested.push_back(source.address);
    else
      excluded.push_back(source.address);
  }
  // Resource exhaustion is atomic. The union is the largest possible source
  // set produced by any RFC 3810 transition below, so accepting this preflight
  // guarantees that no helper silently truncates a Report.
  if (set_union_bounded(set_union_bounded(requested, excluded), incoming)
          .size() > device_catalog::mld_router_sources_per_group) {
    if (created_group)
      groups_.pop_back();
    return false;
  }

  const auto mali = now + multicast_address_listening_interval();
  const auto previous_sources = group->sources;
  const auto set_state = [&](MldFilterMode mode,
                             const std::vector<packet::Ipv6> &active,
                             const std::vector<packet::Ipv6> &blocked,
                             const std::vector<packet::Ipv6> &refresh,
                             Clock::time_point refresh_deadline) {
    group->mode = mode;
    group->sources.clear();
    for (const auto &address : active) {
      const bool refresh_source = contains_address(refresh, address);
      const auto previous = std::find_if(
          previous_sources.begin(), previous_sources.end(),
          [&](const auto &value) { return value.address == address; });
      // Set algebra can retain a source without refreshing its timer. Preserve
      // that exact absolute deadline. A newly introduced active source must be
      // listed in refresh by the transition table and receives its stated J.
      const auto deadline =
          refresh_source
              ? refresh_deadline
              : (previous != previous_sources.end() && previous->timer_running
                     ? previous->expires
                     : refresh_deadline);
      group->sources.push_back(
          {.address = address, .expires = deadline, .timer_running = true});
    }
    for (const auto &address : blocked)
      if (!contains_address(active, address))
        group->sources.push_back({.address = address});
  };

  const auto current_active = requested;
  const auto current_blocked = excluded;
  switch (record.type) {
  case packet::mld::RecordType::mode_is_include:
    if (group->mode == MldFilterMode::include) {
      const auto next = set_union_bounded(current_active, incoming);
      set_state(MldFilterMode::include, next, {}, incoming, mali);
    } else {
      const auto next_active = set_union_bounded(current_active, incoming);
      const auto next_blocked = set_difference(current_blocked, incoming);
      set_state(MldFilterMode::exclude, next_active, next_blocked, incoming,
                mali);
    }
    break;
  case packet::mld::RecordType::mode_is_exclude:
    if (group->mode == MldFilterMode::include) {
      const auto next_active = set_intersection(current_active, incoming);
      const auto next_blocked = set_difference(incoming, current_active);
      set_state(MldFilterMode::exclude, next_active, next_blocked, {}, mali);
    } else {
      const auto next_active = set_difference(incoming, current_blocked);
      const auto next_blocked = set_intersection(current_blocked, incoming);
      const auto newly_requested = set_difference(
          set_difference(incoming, current_active), current_blocked);
      set_state(MldFilterMode::exclude, next_active, next_blocked,
                newly_requested, mali);
    }
    group->filter_timer_running = true;
    group->filter_deadline = mali;
    break;
  case packet::mld::RecordType::allow_new_sources: {
    const auto next_active = set_union_bounded(current_active, incoming);
    const auto next_blocked = set_difference(current_blocked, incoming);
    set_state(group->mode, next_active, next_blocked, incoming, mali);
    break;
  }
  case packet::mld::RecordType::block_old_sources:
    if (!group->older_host_present) {
      const auto query = group->mode == MldFilterMode::include
                             ? set_intersection(current_active, incoming)
                             : set_difference(incoming, current_blocked);
      if (group->mode == MldFilterMode::exclude) {
        const auto next_active = set_union_bounded(
            current_active, set_difference(incoming, current_blocked));
        const auto new_requested = set_difference(
            set_difference(incoming, current_active), current_blocked);
        set_state(MldFilterMode::exclude, next_active, current_blocked,
                  new_requested, group->filter_deadline);
      }
      schedule_query(*group, false, query, now);
    }
    break;
  case packet::mld::RecordType::change_to_exclude: {
    const auto query = group->mode == MldFilterMode::include
                           ? set_intersection(current_active, incoming)
                           : set_difference(incoming, current_blocked);
    const auto next_active = group->mode == MldFilterMode::include
                                 ? set_intersection(current_active, incoming)
                                 : set_difference(incoming, current_blocked);
    const auto next_blocked = group->mode == MldFilterMode::include
                                  ? set_difference(incoming, current_active)
                                  : set_intersection(current_blocked, incoming);
    const auto newly_requested =
        group->mode == MldFilterMode::include
            ? std::vector<packet::Ipv6>{}
            : set_difference(set_difference(incoming, current_active),
                             current_blocked);
    set_state(MldFilterMode::exclude, next_active, next_blocked,
              newly_requested,
              group->filter_timer_running ? group->filter_deadline : mali);
    group->filter_timer_running = true;
    group->filter_deadline = mali;
    if (!group->older_host_present)
      schedule_query(*group, false, query, now);
    break;
  }
  case packet::mld::RecordType::change_to_include: {
    if (group->mode == MldFilterMode::include) {
      const auto query = set_difference(current_active, incoming);
      const auto next = set_union_bounded(current_active, incoming);
      set_state(MldFilterMode::include, next, {}, incoming, mali);
      if (!group->older_host_present)
        schedule_query(*group, false, query, now);
    } else {
      const auto source_query = set_difference(current_active, incoming);
      const auto next_active = set_union_bounded(current_active, incoming);
      const auto next_blocked = set_difference(current_blocked, incoming);
      set_state(MldFilterMode::exclude, next_active, next_blocked, incoming,
                mali);
      if (!group->older_host_present) {
        schedule_query(*group, false, source_query, now);
        schedule_query(*group, true, {}, now);
      }
    }
    break;
  }
  }
  return true;
}

void MldRouterInterface::expire(Clock::time_point now) noexcept {
  if (other_querier_timer_running_ && other_querier_deadline_ <= now) {
    other_querier_timer_running_ = false;
    other_querier_deadline_ = no_deadline;
    querier_ = true;
    querier_address_ = configuration_.link_local_address;
    startup_queries_remaining_ = configuration_.robustness_variable;
    general_query_deadline_ = now;
  }
  if (older_querier_present_ && older_querier_deadline_ <= now) {
    older_querier_present_ = false;
    older_querier_deadline_ = no_deadline;
  }
  for (auto group = groups_.begin(); group != groups_.end();) {
    if (group->older_host_present && group->older_host_deadline <= now) {
      group->older_host_present = false;
      group->older_host_deadline = no_deadline;
    }
    if (group->mode == MldFilterMode::include) {
      std::erase_if(group->sources, [&](const auto &source) {
        return source.timer_running && source.expires <= now;
      });
    } else {
      for (auto &source : group->sources)
        if (source.timer_running && source.expires <= now) {
          source.timer_running = false;
          source.expires = no_deadline;
        }
      if (group->filter_timer_running && group->filter_deadline <= now) {
        group->mode = MldFilterMode::include;
        group->filter_timer_running = false;
        group->filter_deadline = no_deadline;
        std::erase_if(group->sources,
                      [](const auto &source) { return !source.timer_running; });
      }
    }
    const bool pending = std::any_of(
        group->pending_queries.begin(), group->pending_queries.end(),
        [](const auto &query) { return query.transmissions_remaining != 0U; });
    if (group->mode == MldFilterMode::include && group->sources.empty() &&
        !group->older_host_present && !pending)
      group = groups_.erase(group);
    else
      ++group;
  }
}

std::size_t
MldRouterInterface::poll(Clock::time_point now,
                         std::span<MldRouterAction> actions) noexcept {
  if (!configuration_.enabled)
    return 0U;
  expire(now);
  std::size_t produced{};
  if (querier_ && general_query_deadline_ <= now && produced < actions.size()) {
    actions[produced++] = {
        .maximum_response_delay = configuration_.query_response_interval,
        .query_interval = configuration_.query_interval,
        .kind = MldRouterQueryKind::general,
        .robustness_variable = configuration_.robustness_variable,
        .version_one = operational_version() == 1U};
    ++statistics_.queries_transmitted;
    if (startup_queries_remaining_)
      --startup_queries_remaining_;
    general_query_deadline_ =
        now + (startup_queries_remaining_ ? configuration_.query_interval / 4
                                          : configuration_.query_interval);
  }
  for (auto &group : groups_)
    for (auto &query : group.pending_queries) {
      if (produced == actions.size())
        return produced;
      if (!query.transmissions_remaining || query.deadline > now)
        continue;
      auto &action = actions[produced++];
      action = {};
      action.multicast_address = group.multicast_address;
      action.maximum_response_delay =
          configuration_.last_listener_query_interval;
      action.query_interval = configuration_.query_interval;
      action.robustness_variable = configuration_.robustness_variable;
      action.version_one = operational_version() == 1U;
      action.kind = query.multicast_address_query
                        ? MldRouterQueryKind::multicast_address
                        : MldRouterQueryKind::multicast_address_and_sources;
      ++statistics_.queries_transmitted;
      action.source_count = static_cast<std::uint16_t>(query.sources.size());
      std::copy(query.sources.begin(), query.sources.end(),
                action.sources.begin());
      // Subsequent retransmissions suppress repeated timer lowering. The
      // first transmission has already lowered timers in schedule_query.
      action.suppress_router_processing =
          query.transmissions_remaining < configuration_.robustness_variable;
      --query.transmissions_remaining;
      query.deadline = query.transmissions_remaining
                           ? now + configuration_.last_listener_query_interval
                           : no_deadline;
      if (!query.transmissions_remaining)
        query.sources.clear();
    }
  return produced;
}

std::optional<MldRouterInterface::Clock::time_point>
MldRouterInterface::next_deadline() const noexcept {
  if (!configuration_.enabled)
    return std::nullopt;
  auto result = querier_ ? general_query_deadline_ : no_deadline;
  if (other_querier_timer_running_ && other_querier_deadline_ < result)
    result = other_querier_deadline_;
  if (older_querier_present_ && older_querier_deadline_ < result)
    result = older_querier_deadline_;
  for (const auto &group : groups_) {
    if (group.filter_timer_running && group.filter_deadline < result)
      result = group.filter_deadline;
    if (group.older_host_present && group.older_host_deadline < result)
      result = group.older_host_deadline;
    for (const auto &source : group.sources)
      if (source.timer_running && source.expires < result)
        result = source.expires;
    for (const auto &query : group.pending_queries)
      if (query.transmissions_remaining && query.deadline < result)
        result = query.deadline;
  }
  return result == no_deadline ? std::nullopt
                               : std::optional<Clock::time_point>{result};
}

bool MldRouterInterface::listener_accepts(
    const packet::Ipv6 &group_address, const packet::Ipv6 &source_address,
    Clock::time_point now) const noexcept {
  if (!configuration_.enabled)
    return false;
  if (const auto *configured = find_static(group_address);
      configured && (configured->starg ||
                     contains_address(configured->sources, source_address)))
    return true;
  const auto *group = find(group_address);
  if (!group)
    return false;
  const auto source = std::find_if(
      group->sources.begin(), group->sources.end(),
      [&](const auto &entry) { return entry.address == source_address; });
  if (group->mode == MldFilterMode::include)
    return source != group->sources.end() && source->timer_running &&
           source->expires > now;
  // In EXCLUDE mode a missing source or a live requested timer is forwarded;
  // only a zero-timer Exclude List record blocks the source.
  return source == group->sources.end() || source->timer_running;
}

void MldRouterInterface::clear_database(
    const std::optional<packet::Ipv6> &group) noexcept {
  // A group-specific clear erases the complete dynamic listener aggregate,
  // including pending last-listener queries. Retaining those queries after
  // removing their group would let an orphan timer recreate observable wire
  // traffic for state the operator explicitly cleared.
  if (group) {
    std::erase_if(groups_, [&](const auto &entry) {
      return entry.multicast_address == *group;
    });
    return;
  }
  groups_.clear();
}

void MldRouterInterface::clear_older_host_compatibility() noexcept {
  for (auto &group : groups_) {
    group.older_host_present = false;
    group.older_host_deadline = no_deadline;
  }
  older_querier_present_ = false;
  older_querier_deadline_ = no_deadline;
}

MldRouterCheckpoint
MldRouterInterface::checkpoint(Clock::time_point now) const {
  MldRouterCheckpoint state;
  state.configuration = configuration_;
  state.statistics = statistics_;
  state.querier_address = querier_address_;
  state.general_query_remaining_nanoseconds =
      querier_ ? relative(general_query_deadline_, now) : 0;
  state.other_querier_remaining_nanoseconds =
      other_querier_timer_running_ ? relative(other_querier_deadline_, now) : 0;
  state.older_querier_remaining_nanoseconds =
      older_querier_present_ ? relative(older_querier_deadline_, now) : 0;
  state.startup_queries_remaining = startup_queries_remaining_;
  state.querier = querier_;
  state.other_querier_timer_running = other_querier_timer_running_;
  state.older_querier_present = older_querier_present_;
  state.groups.reserve(groups_.size());
  for (const auto &group : groups_) {
    MldRouterGroupCheckpoint output;
    output.multicast_address = group.multicast_address;
    output.mode = group.mode;
    output.filter_timer_running = group.filter_timer_running;
    output.older_host_present = group.older_host_present;
    output.filter_remaining_nanoseconds =
        group.filter_timer_running ? relative(group.filter_deadline, now) : 0;
    output.older_host_remaining_nanoseconds =
        group.older_host_present ? relative(group.older_host_deadline, now) : 0;
    output.sources.reserve(group.sources.size());
    for (const auto &source : group.sources)
      output.sources.push_back(
          {.address = source.address,
           .remaining_nanoseconds =
               source.timer_running ? relative(source.expires, now) : 0,
           .timer_running = source.timer_running});
    for (std::size_t index = 0; index < group.pending_queries.size(); ++index) {
      const auto &input = group.pending_queries[index];
      auto &pending = output.pending_queries[index];
      pending.sources = input.sources;
      pending.remaining_nanoseconds =
          input.transmissions_remaining ? relative(input.deadline, now) : 0;
      pending.transmissions_remaining = input.transmissions_remaining;
      pending.multicast_address_query = input.multicast_address_query;
    }
    state.groups.push_back(std::move(output));
  }
  state.static_groups.reserve(static_groups_.size());
  for (const auto &group : static_groups_)
    state.static_groups.push_back({.multicast_address = group.multicast_address,
                                   .sources = group.sources,
                                   .starg = group.starg});
  return state;
}

bool MldRouterInterface::validate_checkpoint(
    const MldRouterCheckpoint &state) noexcept {
  if (!valid_configuration(state.configuration) ||
      state.groups.size() > device_catalog::mld_router_groups_per_interface ||
      state.static_groups.size() >
          device_catalog::mld_router_groups_per_interface ||
      state.general_query_remaining_nanoseconds < 0 ||
      state.other_querier_remaining_nanoseconds < 0 ||
      state.older_querier_remaining_nanoseconds < 0 ||
      state.startup_queries_remaining >
          state.configuration.robustness_variable ||
      (!state.querier && state.general_query_remaining_nanoseconds != 0) ||
      (!state.other_querier_timer_running &&
       state.other_querier_remaining_nanoseconds != 0) ||
      (!state.older_querier_present &&
       state.older_querier_remaining_nanoseconds != 0) ||
      (state.configuration.enabled &&
       !ip::is_link_local(state.querier_address)) ||
      (!state.configuration.enabled &&
       !ip::is_unspecified(state.querier_address)) ||
      (state.querier && state.other_querier_timer_running))
    return false;
  for (std::size_t index = 0; index < state.static_groups.size(); ++index) {
    const auto &group = state.static_groups[index];
    if (!ip::is_multicast(group.multicast_address) ||
        group.sources.size() > device_catalog::mld_router_sources_per_group ||
        (group.starg && !group.sources.empty()) ||
        std::any_of(group.sources.begin(), group.sources.end(),
                    [](const auto &source) { return !valid_source(source); }))
      return false;
    for (std::size_t other = 0; other < index; ++other)
      if (state.static_groups[other].multicast_address ==
          group.multicast_address)
        return false;
    for (std::size_t source = 0; source < group.sources.size(); ++source)
      if (std::find(group.sources.begin(), group.sources.begin() + source,
                    group.sources[source]) != group.sources.begin() + source)
        return false;
  }
  std::size_t group_source_entries{};
  for (std::size_t index = 0; index < state.groups.size(); ++index) {
    const auto &group = state.groups[index];
    if (!ip::is_multicast(group.multicast_address) ||
        group.sources.size() > device_catalog::mld_router_sources_per_group ||
        group.filter_remaining_nanoseconds < 0 ||
        group.older_host_remaining_nanoseconds < 0 ||
        (!group.filter_timer_running &&
         group.filter_remaining_nanoseconds != 0) ||
        (!group.older_host_present &&
         group.older_host_remaining_nanoseconds != 0))
      return false;
    group_source_entries += group.sources.size();
    if (group_source_entries >
        device_catalog::mld_router_group_sources_per_interface)
      return false;
    for (std::size_t other = 0; other < index; ++other)
      if (state.groups[other].multicast_address == group.multicast_address)
        return false;
    for (std::size_t source_index = 0; source_index < group.sources.size();
         ++source_index) {
      const auto &source = group.sources[source_index];
      if (!valid_source(source.address) || source.remaining_nanoseconds < 0 ||
          (!source.timer_running && source.remaining_nanoseconds != 0))
        return false;
      for (std::size_t other = 0; other < source_index; ++other)
        if (group.sources[other].address == source.address)
          return false;
    }
    for (const auto &pending : group.pending_queries)
      if (pending.sources.size() > device_catalog::mld_sources_per_group ||
          pending.remaining_nanoseconds < 0 ||
          pending.transmissions_remaining >
              state.configuration.robustness_variable ||
          (!pending.transmissions_remaining &&
           (!pending.sources.empty() || pending.remaining_nanoseconds != 0)) ||
          std::any_of(pending.sources.begin(), pending.sources.end(),
                      [](const auto &source) { return !valid_source(source); }))
        return false;
  }
  return true;
}

bool MldRouterInterface::restore(const MldRouterCheckpoint &state,
                                 Clock::time_point now) noexcept {
  if (!validate_checkpoint(state))
    return false;
  std::vector<Group> replacement;
  replacement.reserve(state.groups.size());
  for (const auto &input : state.groups) {
    replacement.emplace_back();
    auto &output = replacement.back();
    output.multicast_address = input.multicast_address;
    output.mode = input.mode;
    output.filter_timer_running = input.filter_timer_running;
    output.older_host_present = input.older_host_present;
    output.filter_deadline =
        input.filter_timer_running
            ? now + std::chrono::nanoseconds{input.filter_remaining_nanoseconds}
            : no_deadline;
    output.older_host_deadline =
        input.older_host_present
            ? now +
                  std::chrono::nanoseconds{
                      input.older_host_remaining_nanoseconds}
            : no_deadline;
    output.sources.reserve(input.sources.size());
    for (const auto &source : input.sources)
      output.sources.push_back(
          {.address = source.address,
           .expires =
               source.timer_running
                   ? now +
                         std::chrono::nanoseconds{source.remaining_nanoseconds}
                   : no_deadline,
           .timer_running = source.timer_running});
    for (std::size_t index = 0; index < input.pending_queries.size(); ++index) {
      const auto &pending = input.pending_queries[index];
      auto &target = output.pending_queries[index];
      target.sources = pending.sources;
      target.sources.reserve(device_catalog::mld_sources_per_group);
      target.transmissions_remaining = pending.transmissions_remaining;
      target.multicast_address_query = pending.multicast_address_query;
      target.deadline =
          pending.transmissions_remaining
              ? now + std::chrono::nanoseconds{pending.remaining_nanoseconds}
              : no_deadline;
    }
  }
  std::vector<StaticGroup> static_replacement;
  static_replacement.reserve(state.static_groups.size());
  for (const auto &input : state.static_groups) {
    static_replacement.push_back({.multicast_address = input.multicast_address,
                                  .sources = input.sources,
                                  .starg = input.starg});
    // The copied vector already owns exactly the restored source count. No
    // maximum-size reservation is performed for an otherwise small group.
  }
  configuration_ = state.configuration;
  statistics_ = state.statistics;
  groups_.swap(replacement);
  static_groups_.swap(static_replacement);
  startup_queries_remaining_ = state.startup_queries_remaining;
  querier_ = state.querier;
  other_querier_timer_running_ = state.other_querier_timer_running;
  older_querier_present_ = state.older_querier_present;
  querier_address_ = state.querier_address;
  general_query_deadline_ =
      querier_ ? now +
                     std::chrono::nanoseconds{
                         state.general_query_remaining_nanoseconds}
               : no_deadline;
  other_querier_deadline_ =
      other_querier_timer_running_
          ? now +
                std::chrono::nanoseconds{
                    state.other_querier_remaining_nanoseconds}
          : no_deadline;
  older_querier_deadline_ =
      older_querier_present_
          ? now +
                std::chrono::nanoseconds{
                    state.older_querier_remaining_nanoseconds}
          : no_deadline;
  return true;
}

} // namespace router::lab
