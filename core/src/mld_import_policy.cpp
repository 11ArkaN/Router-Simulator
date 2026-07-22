// MLD import-policy evaluation. This module knows only canonical IPv6 values
// and ordered policy entries. It cannot mutate listener state, inspect a
// topology or call another device, which keeps policy admission at the local
// forwarding-owner boundary.

#include "router/mld_import_policy.hpp"

#include <algorithm>
#include <new>

namespace router::mld {
namespace {

bool valid_prefix(const ip::Ipv6Prefix &prefix) noexcept {
  // Policy-options prefix lists are generic IPv6 prefix sets. SR OS does not
  // narrow the configured list merely because an MLD consumer later uses it
  // as group-address or source-address. The packet being evaluated already
  // supplies a multicast group and, when present, a unicast source. Requiring
  // the stored prefix itself to be wholly multicast or unicast would wrongly
  // reject useful matches such as ::/0 and would add a simulator-only rule.
  return prefix.length <= ip::ipv6_address_bits &&
         ip::mask(prefix.network, prefix.length) == prefix.network;
}

} // namespace

bool ImportPolicyProgram::valid(
    std::span<const ImportPolicyEntry> entries,
    ImportPolicyAction default_action) noexcept {
  if (default_action == ImportPolicyAction::next_entry ||
      default_action > ImportPolicyAction::next_policy)
    return false;
  std::uint32_t previous{};
  std::uint32_t previous_term{};
  bool first = true;
  for (const auto &entry : entries) {
    if (!entry.number ||
        (!first && (entry.number < previous ||
                    (entry.number == previous &&
                     entry.term <= previous_term))) ||
        (entry.group && !valid_prefix(*entry.group)) ||
        (entry.source && !valid_prefix(*entry.source)))
      return false;
    first = false;
    previous = entry.number;
    previous_term = entry.term;
  }
  return true;
}

bool ImportPolicyProgram::replace(
    std::span<const ImportPolicyEntry> entries,
    ImportPolicyAction default_action) noexcept {
  if (!valid(entries, default_action))
    return false;
  try {
    // Construct before assigning so allocation failure cannot erase the
    // currently active generation. Entries are already ordered and require no
    // hot-path sort or pointer graph after publication.
    std::vector<ImportPolicyEntry> next{entries.begin(), entries.end()};
    entries_ = std::move(next);
    default_action_ = default_action;
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

ImportPolicyAction ImportPolicyProgram::evaluate(
    const ip::Ipv6 &group,
    const std::optional<ip::Ipv6> &source) const noexcept {
  for (const auto &entry : entries_) {
    // This program is invoked only for MLD. A configured protocol=mld clause
    // therefore matches, while absence means the entry applies to every
    // protocol consumer and also matches here.
    if (entry.group && !ip::contains(*entry.group, group))
      continue;
    if (entry.source &&
        (!source || !ip::contains(*entry.source, *source)))
      continue;
    if (entry.action != ImportPolicyAction::next_entry)
      return entry.action;
  }
  return default_action_;
}

ImportPolicyCheckpoint ImportPolicyProgram::checkpoint() const {
  return {.entries = entries_, .default_action = default_action_};
}

bool ImportPolicyProgram::restore(
    const ImportPolicyCheckpoint &state) noexcept {
  return replace(state.entries, state.default_action);
}

} // namespace router::mld
