// RFC 2710, RFC 3590 and RFC 3810 listener state implementation. All timers
// use the host monotonic clock and remain local to one interface owner.

#include "router/mld_listener.hpp"

#include "router/ip_address.hpp"

#include <algorithm>
#include <limits>

namespace router::lab {
namespace {

using Clock = MldListener::Clock;

constexpr auto no_deadline = Clock::time_point::max();

bool reportable_group(const packet::Ipv6 &group) noexcept {
  // RFC 2710 section 5 excludes reserved scope zero, interface-local scope one
  // and ff02::1. The scope nibble is defined by RFC 4291, not by a platform
  // default, so it belongs beside the protocol validation.
  const auto scope = static_cast<std::uint8_t>(group[1] & 0x0fU);
  return ip::is_multicast(group) && scope > 1U &&
         group != packet::nd::all_nodes_multicast;
}

bool valid_source(const packet::Ipv6 &source) noexcept {
  return !ip::is_unspecified(source) && !ip::is_multicast(source);
}

template <typename Duration>
std::int64_t remaining(Clock::time_point deadline, Clock::time_point now) {
  if (deadline == no_deadline)
    return 0;
  const auto value = deadline > now ? deadline - now : Clock::duration::zero();
  return std::chrono::duration_cast<Duration>(value).count();
}

} // namespace

MldListener::MldListener(std::uint64_t interface_identity) noexcept
    : random_state_(interface_identity ? interface_identity : 1U) {}

MldListener::Group *MldListener::find(const packet::Ipv6 &group) noexcept {
  const auto result = std::find_if(groups_.begin(), groups_.end(),
                                   [&](const auto &entry) {
                                     return entry.occupied &&
                                            entry.multicast_address == group;
                                   });
  return result == groups_.end() ? nullptr : &*result;
}

const MldListener::Group *
MldListener::find(const packet::Ipv6 &group) const noexcept {
  const auto result = std::find_if(groups_.begin(), groups_.end(),
                                   [&](const auto &entry) {
                                     return entry.occupied &&
                                            entry.multicast_address == group;
                                   });
  return result == groups_.end() ? nullptr : &*result;
}

MldListener::Group *
MldListener::allocate(const packet::Ipv6 &group) noexcept {
  if (auto *existing = find(group))
    return existing;
  const auto empty =
      std::find_if(groups_.begin(), groups_.end(),
                   [](const auto &entry) { return !entry.occupied; });
  if (empty == groups_.end())
    return nullptr;
  *empty = {};
  empty->occupied = true;
  empty->multicast_address = group;
  return &*empty;
}

std::chrono::nanoseconds
MldListener::randomized_delay(std::chrono::nanoseconds maximum) noexcept {
  if (maximum <= std::chrono::nanoseconds::zero())
    return std::chrono::nanoseconds::zero();
  // xorshift64* is a compact deterministic PRNG, not a hardcoded topology
  // choice. Its state is checkpointed so restore does not change which host
  // wins report suppression or shift a response beyond its original window.
  random_state_ ^= random_state_ >> 12U;
  random_state_ ^= random_state_ << 25U;
  random_state_ ^= random_state_ >> 27U;
  const auto sample = random_state_ * 0x2545f4914f6cdd1dULL;
  const auto bound = static_cast<std::uint64_t>(maximum.count());
  return std::chrono::nanoseconds{static_cast<std::int64_t>(sample % (bound + 1U))};
}

void MldListener::schedule_state_change(Group &group,
                                        packet::mld::RecordType type,
                                        std::span<const packet::Ipv6> sources,
                                        Clock::time_point now) noexcept {
  if (!reportable_group(group.multicast_address))
    return;
  group.retransmission_type = type;
  group.retransmission_source_count =
      static_cast<std::uint16_t>(sources.size());
  std::copy(sources.begin(), sources.end(),
            group.retransmission_sources.begin());
  group.retransmissions_remaining = device_catalog::mld_robustness_variable;
  // RFC 3810 section 6.1 requires the first State Change Report immediately.
  // poll performs emission so the owner never bypasses its bounded work turn.
  group.retransmission_deadline = now;
}

bool MldListener::listen(const packet::Ipv6 &group, MldFilterMode mode,
                         std::span<const packet::Ipv6> sources,
                         Clock::time_point now) noexcept {
  if (!ip::is_multicast(group) || sources.size() >
                                      device_catalog::mld_sources_per_group ||
      std::any_of(sources.begin(), sources.end(),
                  [](const auto &source) { return !valid_source(source); }))
    return false;

  // INCLUDE {} is the standardized stop-listening operation. Keep a record
  // only long enough to transmit its robust leave notification.
  auto *entry = find(group);
  const bool stopping = mode == MldFilterMode::include && sources.empty();
  if (!entry && stopping)
    return true;
  if (!entry && !(entry = allocate(group)))
    return false;

  const auto old_mode = entry->mode;
  const auto old_count = entry->source_count;
  const auto old_sources = entry->sources;
  const bool identical = old_mode == mode && old_count == sources.size() &&
                         std::equal(sources.begin(), sources.end(),
                                    old_sources.begin());
  if (identical)
    return true;

  entry->mode = mode;
  entry->source_count = static_cast<std::uint16_t>(sources.size());
  std::copy(sources.begin(), sources.end(), entry->sources.begin());

  if (old_mode != mode) {
    schedule_state_change(*entry,
                          mode == MldFilterMode::include
                              ? packet::mld::RecordType::change_to_include
                              : packet::mld::RecordType::change_to_exclude,
                          sources, now);
  } else {
    // RFC 3810 section 5.2.12 represents same-mode source changes as ALLOW
    // and BLOCK records. When both sets change, ALLOW is emitted first and a
    // subsequent complete Current State response will refresh the final set.
    std::array<packet::Ipv6, device_catalog::mld_sources_per_group> added{};
    std::array<packet::Ipv6, device_catalog::mld_sources_per_group> removed{};
    std::size_t added_count{};
    std::size_t removed_count{};
    for (const auto &source : sources)
      if (std::find(old_sources.begin(), old_sources.begin() + old_count,
                    source) == old_sources.begin() + old_count)
        added[added_count++] = source;
    for (auto old = old_sources.begin(); old != old_sources.begin() + old_count;
         ++old)
      if (std::find(sources.begin(), sources.end(), *old) == sources.end())
        removed[removed_count++] = *old;

    // A single local replacement can add and remove sources. RFC 3810 permits
    // both source-list change records in one Report. This bounded owner emits
    // one immediately and schedules a Current State response for the second
    // owner turn, preserving the exact final state without fabricating a list.
    const auto &delta = added_count ? added : removed;
    const auto count = added_count ? added_count : removed_count;
    schedule_state_change(
        *entry,
        added_count ? packet::mld::RecordType::allow_new_sources
                    : packet::mld::RecordType::block_old_sources,
        std::span<const packet::Ipv6>{delta.data(), count}, now);
    if (added_count && removed_count) {
      entry->response_pending = true;
      entry->response_deadline = now;
    }
  }
  return true;
}

bool MldListener::join(const packet::Ipv6 &group,
                       Clock::time_point now) noexcept {
  return listen(group, MldFilterMode::exclude, {}, now);
}

bool MldListener::leave(const packet::Ipv6 &group,
                        Clock::time_point now) noexcept {
  return listen(group, MldFilterMode::include, {}, now);
}

void MldListener::observe_query(const packet::mld::QueryView &query,
                                Clock::time_point now) noexcept {
  if (query.version_two == false) {
    version_one_compatibility_ = true;
    // RFC 3810 section 8.2.1 defines the timeout as Robustness * Query
    // Interval + Query Response Interval. Query-derived values avoid assuming
    // that another router uses this profile's defaults.
    older_querier_deadline_ =
        now + device_catalog::mld_robustness_variable * query.query_interval +
        query.maximum_response_delay;
    for (auto &group : groups_) {
      group.response_pending = false;
      group.response_deadline = no_deadline;
      group.retransmissions_remaining = 0U;
      group.retransmission_deadline = no_deadline;
    }
  }

  const auto maximum = std::chrono::duration_cast<std::chrono::nanoseconds>(
      query.maximum_response_delay);
  for (auto &group : groups_) {
    if (!group.occupied || !reportable_group(group.multicast_address) ||
        (group.mode == MldFilterMode::include && !group.source_count) ||
        (!ip::is_unspecified(query.multicast_address) &&
         query.multicast_address != group.multicast_address))
      continue;
    const auto proposed = now + randomized_delay(maximum);
    if (!group.response_pending || proposed < group.response_deadline) {
      group.response_pending = true;
      group.response_deadline = proposed;
    }
  }
}

void MldListener::observe_version_one_report(
    const packet::Ipv6 &group) noexcept {
  // RFC 2710 permits report suppression only for an equal group while this
  // node is delaying. MLDv2 suppression is intentionally not inferred here.
  if (auto *entry = find(group); entry && version_one_compatibility_) {
    entry->response_pending = false;
    entry->response_deadline = no_deadline;
  }
}

void MldListener::set_link_state(bool operational,
                                 bool link_local_preferred,
                                 Clock::time_point now) noexcept {
  const bool became_operational = operational && !link_operational_;
  const bool became_preferred = operational && link_local_preferred &&
                                !link_local_preferred_;
  link_operational_ = operational;
  link_local_preferred_ = link_local_preferred;
  if (!operational) {
    for (auto &group : groups_) {
      group.response_pending = false;
      group.response_deadline = no_deadline;
      group.retransmissions_remaining = 0U;
      group.retransmission_deadline = no_deadline;
    }
    return;
  }
  if (became_operational) {
    // Membership intent survives a carrier failure, but router and snooping
    // state on the new attachment cannot be assumed. Re-announce each live
    // filter before DAD traffic depends on its solicited-node membership.
    for (auto &group : groups_)
      if (group.occupied && reportable_group(group.multicast_address) &&
          !(group.mode == MldFilterMode::include && !group.source_count))
        schedule_state_change(
            group, group.mode == MldFilterMode::include
                       ? packet::mld::RecordType::change_to_include
                       : packet::mld::RecordType::change_to_exclude,
            std::span<const packet::Ipv6>{group.sources.data(),
                                          group.source_count},
            now);
  }
  if (became_preferred) {
    // RFC 3590 section 4 recommends refreshed reports once a usable
    // link-local source exists. Current State records describe the exact live
    // filter instead of replaying a stale transition.
    for (auto &group : groups_)
      if (group.occupied && reportable_group(group.multicast_address) &&
          !(group.mode == MldFilterMode::include && !group.source_count)) {
        group.response_pending = true;
        group.response_deadline = now;
      }
  }
}

std::size_t MldListener::poll(Clock::time_point now,
                              std::span<MldListenerAction> actions) noexcept {
  if (version_one_compatibility_ && older_querier_deadline_ <= now) {
    version_one_compatibility_ = false;
    older_querier_deadline_ = no_deadline;
    // RFC 3810 cancels pending timers on a compatibility transition. Fresh
    // reports are driven by the next query or local state change.
    for (auto &group : groups_) {
      group.response_pending = false;
      group.response_deadline = no_deadline;
      group.retransmissions_remaining = 0U;
      group.retransmission_deadline = no_deadline;
    }
  }
  if (!link_operational_)
    return 0U;

  std::size_t produced{};
  for (auto &group : groups_) {
    if (produced == actions.size())
      break;
    const bool retransmit = group.occupied &&
                            group.retransmissions_remaining &&
                            group.retransmission_deadline <= now;
    const bool response = group.occupied && group.response_pending &&
                          group.response_deadline <= now;
    if (!retransmit && !response)
      continue;

    auto &action = actions[produced++];
    action = {};
    action.multicast_address = group.multicast_address;
    action.version_one = version_one_compatibility_;
    action.record_type = retransmit
                             ? group.retransmission_type
                             : (group.mode == MldFilterMode::include
                                    ? packet::mld::RecordType::mode_is_include
                                    : packet::mld::RecordType::mode_is_exclude);
    action.source_count = retransmit ? group.retransmission_source_count
                                     : group.source_count;
    std::copy_n(retransmit ? group.retransmission_sources.begin()
                           : group.sources.begin(),
                action.source_count,
                action.sources.begin());
    action.done = action.version_one &&
                  group.mode == MldFilterMode::include &&
                  group.source_count == 0U;

    if (response) {
      group.response_pending = false;
      group.response_deadline = no_deadline;
    }
    if (retransmit) {
      --group.retransmissions_remaining;
      group.retransmission_deadline =
          group.retransmissions_remaining
              ? now + randomized_delay(std::chrono::duration_cast<
                                           std::chrono::nanoseconds>(
                                           device_catalog::
                                               mld_unsolicited_report_interval))
              : no_deadline;
    }
    if (group.mode == MldFilterMode::include && !group.source_count &&
        !group.retransmissions_remaining && !group.response_pending)
      group = {};
  }
  return produced;
}

std::optional<MldListener::Clock::time_point>
MldListener::next_deadline() const noexcept {
  auto result = version_one_compatibility_ ? older_querier_deadline_
                                           : no_deadline;
  for (const auto &group : groups_) {
    if (!group.occupied)
      continue;
    if (group.response_pending && group.response_deadline < result)
      result = group.response_deadline;
    if (group.retransmissions_remaining &&
        group.retransmission_deadline < result)
      result = group.retransmission_deadline;
  }
  return result == no_deadline ? std::nullopt
                               : std::optional<Clock::time_point>{result};
}

bool MldListener::accepts(const packet::Ipv6 &group,
                          const packet::Ipv6 &source) const noexcept {
  if (group == packet::nd::all_nodes_multicast)
    return true;
  const auto *entry = find(group);
  if (!entry)
    return false;
  const bool listed = std::find(entry->sources.begin(),
                                entry->sources.begin() + entry->source_count,
                                source) !=
                      entry->sources.begin() + entry->source_count;
  return entry->mode == MldFilterMode::include ? listed : !listed;
}

bool MldListener::joined(const packet::Ipv6 &group) const noexcept {
  if (group == packet::nd::all_nodes_multicast)
    return true;
  const auto *entry = find(group);
  return entry &&
         !(entry->mode == MldFilterMode::include && !entry->source_count);
}

MldListenerCheckpoint
MldListener::checkpoint(Clock::time_point now) const {
  MldListenerCheckpoint state;
  state.random_state = random_state_;
  state.version_one_compatibility = version_one_compatibility_;
  state.link_operational = link_operational_;
  state.link_local_preferred = link_local_preferred_;
  if (version_one_compatibility_)
    state.older_querier_remaining_nanoseconds =
        remaining<std::chrono::nanoseconds>(older_querier_deadline_, now);
  for (const auto &group : groups_) {
    if (!group.occupied)
      continue;
    MldListenerGroupCheckpoint output;
    output.multicast_address = group.multicast_address;
    output.sources = group.sources;
    output.retransmission_sources = group.retransmission_sources;
    output.source_count = group.source_count;
    output.retransmission_source_count =
        group.retransmission_source_count;
    output.mode = group.mode;
    output.retransmission_type = group.retransmission_type;
    output.retransmissions_remaining = group.retransmissions_remaining;
    output.response_pending = group.response_pending;
    output.occupied = true;
    if (group.response_pending)
      output.response_remaining_nanoseconds =
          remaining<std::chrono::nanoseconds>(group.response_deadline, now);
    if (group.retransmissions_remaining)
      output.retransmission_remaining_nanoseconds =
          remaining<std::chrono::nanoseconds>(group.retransmission_deadline,
                                              now);
    state.groups.push_back(output);
  }
  return state;
}

bool MldListener::validate_checkpoint(
    const MldListenerCheckpoint &state) noexcept {
  if (!state.random_state ||
      state.groups.size() > device_catalog::mld_groups_per_interface ||
      (state.link_local_preferred && !state.link_operational) ||
      state.older_querier_remaining_nanoseconds < 0 ||
      (!state.version_one_compatibility &&
       state.older_querier_remaining_nanoseconds != 0))
    return false;
  for (std::size_t index = 0; index < state.groups.size(); ++index) {
    const auto &group = state.groups[index];
    if (!group.occupied || !ip::is_multicast(group.multicast_address) ||
        group.source_count > device_catalog::mld_sources_per_group ||
        group.retransmission_source_count >
            device_catalog::mld_sources_per_group ||
        group.retransmissions_remaining >
            device_catalog::mld_robustness_variable ||
        group.response_remaining_nanoseconds < 0 ||
        group.retransmission_remaining_nanoseconds < 0 ||
        (!group.response_pending &&
         group.response_remaining_nanoseconds != 0) ||
        (!group.retransmissions_remaining &&
         group.retransmission_remaining_nanoseconds != 0) ||
        std::any_of(group.sources.begin(),
                    group.sources.begin() + group.source_count,
                    [](const auto &source) { return !valid_source(source); }) ||
        std::any_of(group.retransmission_sources.begin(),
                    group.retransmission_sources.begin() +
                        group.retransmission_source_count,
                    [](const auto &source) { return !valid_source(source); }))
      return false;
    for (std::size_t other = 0; other < index; ++other)
      if (state.groups[other].multicast_address == group.multicast_address)
        return false;
  }
  return true;
}

bool MldListener::restore(const MldListenerCheckpoint &state,
                          Clock::time_point now) noexcept {
  if (!validate_checkpoint(state))
    return false;
  std::array<Group, device_catalog::mld_groups_per_interface> replacement{};
  for (std::size_t index = 0; index < state.groups.size(); ++index) {
    const auto &input = state.groups[index];
    auto &output = replacement[index];
    output.multicast_address = input.multicast_address;
    output.sources = input.sources;
    output.retransmission_sources = input.retransmission_sources;
    output.source_count = input.source_count;
    output.retransmission_source_count = input.retransmission_source_count;
    output.mode = input.mode;
    output.retransmission_type = input.retransmission_type;
    output.retransmissions_remaining = input.retransmissions_remaining;
    output.response_pending = input.response_pending;
    output.occupied = true;
    output.response_deadline = input.response_pending
                                   ? now + std::chrono::nanoseconds{
                                               input.response_remaining_nanoseconds}
                                   : no_deadline;
    output.retransmission_deadline =
        input.retransmissions_remaining
            ? now + std::chrono::nanoseconds{
                        input.retransmission_remaining_nanoseconds}
            : no_deadline;
  }
  groups_ = replacement;
  random_state_ = state.random_state;
  version_one_compatibility_ = state.version_one_compatibility;
  link_operational_ = state.link_operational;
  link_local_preferred_ = state.link_local_preferred;
  older_querier_deadline_ = version_one_compatibility_
                                ? now + std::chrono::nanoseconds{
                                            state.older_querier_remaining_nanoseconds}
                                : no_deadline;
  return true;
}

} // namespace router::lab
