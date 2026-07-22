// Pure RFC 6724 comparison implementation. Rules are evaluated in normative
// order and the first decisive rule wins. Equal candidates preserve input
// order, making the caller's stable address order the deterministic fallback.

#include "router/ipv6_source_selection.hpp"

#include <array>

namespace router::ip {
namespace {

struct PolicyRow {
  Ipv6Prefix prefix{};
  std::uint8_t label{};
};

// This is the RFC 6724 Section 2.1 default label table, ordered by descending
// prefix length. Precedence is a destination-selection property and is not
// copied into this source-selection-only module.
constexpr std::array default_policy{
    PolicyRow{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 128}, 0},
    PolicyRow{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0}, 96}, 4},
    PolicyRow{{{}, 96}, 3},
    PolicyRow{{{0x20, 0x01}, 32}, 5},
    PolicyRow{{{0x20, 0x02}, 16}, 2},
    PolicyRow{{{0x3f, 0xfe}, 16}, 12},
    PolicyRow{{{0xfe, 0xc0}, 10}, 11},
    PolicyRow{{{0xfc}, 7}, 13},
    PolicyRow{{{}, 0}, 1}};

enum class Preference : std::int8_t { second = -1, equal = 0, first = 1 };

Preference boolean_preference(bool first, bool second) noexcept {
  if (first == second)
    return Preference::equal;
  return first ? Preference::first : Preference::second;
}

Preference compare(const Ipv6SourceCandidate &first,
                   const Ipv6SourceCandidate &second,
                   const Ipv6SourceSelectionContext &context) noexcept {
  // Rule 1 is intentionally ahead of deprecation. A deprecated address equal
  // to the destination remains preferable to a different preferred address.
  if (const auto rule = boolean_preference(first.address == context.destination,
                                           second.address == context.destination);
      rule != Preference::equal)
    return rule;

  // Rule 2 prefers the smallest scope that is still large enough. When only
  // one candidate is too narrow for the destination, it necessarily loses.
  const auto destination_scope = ipv6_scope(context.destination);
  const auto first_scope = ipv6_scope(first.address);
  const auto second_scope = ipv6_scope(second.address);
  if (first_scope != second_scope) {
    if (first_scope < second_scope)
      return first_scope < destination_scope ? Preference::second
                                             : Preference::first;
    return second_scope < destination_scope ? Preference::first
                                            : Preference::second;
  }

  if (const auto rule = boolean_preference(first.preferred, second.preferred);
      rule != Preference::equal)
    return rule;

  // Rule 4 models the two mobility attributes independently. A value that is
  // both home and care-of wins first, followed by home over care-of.
  const auto first_both = first.home && first.care_of;
  const auto second_both = second.home && second.care_of;
  if (const auto rule = boolean_preference(first_both, second_both);
      rule != Preference::equal)
    return rule;
  if (first.home != second.home && first.care_of != second.care_of)
    return first.home ? Preference::first : Preference::second;

  if (const auto rule = boolean_preference(
          first.interface_id == context.outgoing_interface_id,
          second.interface_id == context.outgoing_interface_id);
      rule != Preference::equal)
    return rule;

  // Rule 5.5 applies only when the owner actually records which next hop
  // advertised each prefix. A false tracking flag prevents fabricated data
  // from influencing selection.
  if (context.track_advertising_next_hop)
    if (const auto rule = boolean_preference(first.advertised_by_next_hop,
                                             second.advertised_by_next_hop);
        rule != Preference::equal)
      return rule;

  if (const auto rule = boolean_preference(
          ipv6_policy_label(first.address) ==
              ipv6_policy_label(context.destination),
          ipv6_policy_label(second.address) ==
              ipv6_policy_label(context.destination));
      rule != Preference::equal)
    return rule;

  if (first.temporary != second.temporary)
    return first.temporary == context.prefer_temporary ? Preference::first
                                                       : Preference::second;

  const auto first_prefix = ipv6_common_prefix_length(
      first.address, context.destination, first.prefix_length);
  const auto second_prefix = ipv6_common_prefix_length(
      second.address, context.destination, second.prefix_length);
  if (first_prefix != second_prefix)
    return first_prefix > second_prefix ? Preference::first
                                        : Preference::second;
  return Preference::equal;
}

} // namespace

Ipv6Scope ipv6_scope(const Ipv6 &address) noexcept {
  if (is_multicast(address)) {
    switch (address[1] & 0x0fU) {
    case 1:
      return Ipv6Scope::interface_local;
    case 2:
      return Ipv6Scope::link_local;
    case 4:
      return Ipv6Scope::admin_local;
    case 5:
      return Ipv6Scope::site_local;
    case 8:
      return Ipv6Scope::organization_local;
    default:
      return Ipv6Scope::global;
    }
  }
  if (is_link_local(address) || is_loopback(address))
    return Ipv6Scope::link_local;
  // Deprecated site-local unicast remains part of RFC 6724 comparison even
  // though new configuration should not create such an address.
  if (address[0] == 0xfeU && (address[1] & 0xc0U) == 0xc0U)
    return Ipv6Scope::site_local;
  return Ipv6Scope::global;
}

std::uint8_t ipv6_policy_label(const Ipv6 &address) noexcept {
  for (const auto &row : default_policy)
    if (contains(row.prefix, address))
      return row.label;
  // The final ::/0 row is exhaustive. This return protects the function from
  // an accidental future table edit without introducing an uninitialized path.
  return 1;
}

std::uint8_t ipv6_common_prefix_length(const Ipv6 &first, const Ipv6 &second,
                                       std::uint8_t maximum) noexcept {
  if (maximum > ipv6_address_bits)
    maximum = ipv6_address_bits;
  std::uint8_t result{};
  for (std::size_t index = 0; index < first.size() && result < maximum;
       ++index) {
    const auto differing = static_cast<std::uint8_t>(first[index] ^ second[index]);
    for (std::uint8_t bit = 0; bit < 8U && result < maximum; ++bit) {
      if ((differing & static_cast<std::uint8_t>(0x80U >> bit)) != 0U)
        return result;
      ++result;
    }
  }
  return result;
}

std::optional<std::size_t> select_ipv6_source(
    std::span<const Ipv6SourceCandidate> candidates,
    const Ipv6SourceSelectionContext &context) noexcept {
  std::optional<std::size_t> selected;
  for (std::size_t index = 0; index < candidates.size(); ++index) {
    const auto &candidate = candidates[index];
    if (candidate.prefix_length > ipv6_address_bits ||
        is_unspecified(candidate.address) || is_multicast(candidate.address))
      continue;
    // A link-scoped destination cannot borrow a source from another link.
    if ((is_link_local(context.destination) ||
         (is_multicast(context.destination) &&
          ipv6_scope(context.destination) <= Ipv6Scope::link_local)) &&
        candidate.interface_id != context.outgoing_interface_id)
      continue;
    if (!selected || compare(candidate, candidates[*selected], context) ==
                         Preference::first)
      selected = index;
  }
  return selected;
}

} // namespace router::ip
