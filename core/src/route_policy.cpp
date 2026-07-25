// Route-policy generation validation and first-match evaluation. Prefix and
// protocol matching use only the supplied route candidate, preventing policy
// code from querying the topology or another router's state.

#include "router/route_policy.hpp"

#include <algorithm>
#include <new>

namespace router::lab::routing {
namespace {

[[nodiscard]] bool canonical(const PolicyPrefix &prefix) noexcept {
  if (!prefix.ipv6)
    return prefix.length <= 32U &&
           (prefix.ipv4_network & prefix_mask(prefix.length)) ==
               prefix.ipv4_network;
  return prefix.length <= ip::ipv6_address_bits &&
         ip::mask(prefix.ipv6_network, prefix.length) == prefix.ipv6_network;
}

[[nodiscard]] bool contains(const PolicyPrefix &outer,
                            const PolicyPrefix &inner) noexcept {
  if (outer.ipv6 != inner.ipv6 || outer.length > inner.length)
    return false;
  if (!outer.ipv6)
    return (inner.ipv4_network & prefix_mask(outer.length)) ==
           outer.ipv4_network;
  return ip::contains(
      ip::Ipv6Prefix{.network = outer.ipv6_network, .length = outer.length},
      inner.ipv6_network);
}

[[nodiscard]] bool matches(const PolicyEntry &entry,
                           const PolicyCandidate &candidate) noexcept {
  return (!entry.destination ||
          contains(*entry.destination, candidate.destination)) &&
         (!entry.source || *entry.source == candidate.source) &&
         (!entry.protocol_instance ||
          *entry.protocol_instance == candidate.protocol_instance) &&
         (!entry.tag || *entry.tag == candidate.tag);
}

} // namespace

bool RoutePolicyProgram::valid(std::span<const PolicyEntry> entries,
                               PolicyDecision default_decision) noexcept {
  if (default_decision == PolicyDecision::next_entry)
    return false;
  std::uint32_t previous{};
  std::uint32_t previous_term{};
  bool first = true;
  for (const auto &entry : entries) {
    if (!entry.number ||
        (!first &&
         (entry.number < previous ||
          (entry.number == previous && entry.term <= previous_term))) ||
        (entry.destination && !canonical(*entry.destination)) ||
        (entry.set_metric_type &&
         *entry.set_metric_type != OspfPathType::external_type_1 &&
         *entry.set_metric_type != OspfPathType::external_type_2 &&
         *entry.set_metric_type != OspfPathType::nssa_type_1 &&
         *entry.set_metric_type != OspfPathType::nssa_type_2))
      return false;
    previous = entry.number;
    previous_term = entry.term;
    first = false;
  }
  return true;
}

bool RoutePolicyProgram::replace(std::span<const PolicyEntry> entries,
                                 PolicyDecision default_decision) noexcept {
  if (!valid(entries, default_decision))
    return false;
  try {
    std::vector<PolicyEntry> next{entries.begin(), entries.end()};
    entries_ = std::move(next);
    default_decision_ = default_decision;
    return true;
  } catch (const std::bad_alloc &) {
    // A failed allocation is a rejected configuration generation, never a
    // reason to erase the policy that currently protects redistribution.
    return false;
  }
}

PolicyResult
RoutePolicyProgram::evaluate(const PolicyCandidate &candidate) const noexcept {
  PolicyResult result{.candidate = candidate};
  for (const auto &entry : entries_) {
    if (!matches(entry, result.candidate))
      continue;
    // Attribute actions precede the disposition of the same entry. next-entry
    // deliberately carries the modified candidate into subsequent clauses,
    // matching ordered route-policy processing rather than restarting from the
    // original source route.
    if (entry.set_metric)
      result.candidate.metric = *entry.set_metric;
    if (entry.set_metric_type)
      result.candidate.ospf_path_type = *entry.set_metric_type;
    if (entry.set_tag)
      result.candidate.tag = *entry.set_tag;
    if (entry.decision != PolicyDecision::next_entry) {
      result.decision = entry.decision;
      return result;
    }
  }
  result.decision = default_decision_;
  return result;
}

} // namespace router::lab::routing
