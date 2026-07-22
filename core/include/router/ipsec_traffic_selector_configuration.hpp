// Control-owned SR OS IKEv2 traffic selector list intent. This module stores
// canonical addresses and protocol ranges only. The IKE owner converts local
// and remote entries into TS payloads, while the forwarding owner compiles the
// negotiated result into SPD indexes. Neither owner can mutate this value.

#pragma once

#include "router/generated_profile.hpp"
#include "router/ipsec_policy.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace router::ipsec::configuration {

enum class SelectorProtocol : std::uint8_t {
  any = 0U,
  icmp = 1U,
  tcp = 6U,
  udp = 17U,
  ipv6_mobility = 135U,
  icmpv6 = 58U,
  sctp = 132U,
  numeric = 255U
};

struct TrafficSelectorEntry {
  std::uint8_t id{};
  // SR OS requires either one prefix or an inclusive address range. A prefix
  // is already canonical. Range endpoints retain their address family and are
  // ordered during validation before candidate commit.
  std::optional<ipsec::Prefix> prefix;
  std::optional<ipsec::Address> range_begin;
  std::optional<ipsec::Address> range_end;
  SelectorProtocol protocol{SelectorProtocol::any};
  std::uint8_t numeric_protocol{};
  ipsec::PortRange ports{};
  bool opaque_ports{};
  bool protocol_configured{};
  // MD-CLI exposes the bounds as individual mandatory leaves. Presence is
  // therefore distinct from the numeric value zero and must survive a private
  // candidate checkpoint. Classic CLI sets both flags atomically.
  bool selector_begin_configured{};
  bool selector_end_configured{};
  // ICMP and ICMPv6 split each 16-bit selector bound into independent type
  // and code leaves. Four flags are necessary because a private MD candidate
  // may legally contain any subset until commit validation. The packed value
  // in `ports` remains the canonical RFC 7296 wire representation.
  bool begin_icmp_type_configured{};
  bool begin_icmp_code_configured{};
  bool end_icmp_type_configured{};
  bool end_icmp_code_configured{};

  bool operator==(const TrafficSelectorEntry &) const = default;
};

struct TrafficSelectorList {
  std::string name;
  std::vector<TrafficSelectorEntry> local;
  std::vector<TrafficSelectorEntry> remote;

  bool operator==(const TrafficSelectorList &) const = default;
};

[[nodiscard]] inline TrafficSelectorList *
find_traffic_selector_list(std::vector<TrafficSelectorList> &lists,
                           std::string_view name) noexcept {
  const auto found = std::find_if(lists.begin(), lists.end(),
                                  [name](const auto &item) {
                                    return item.name == name;
                                  });
  return found == lists.end() ? nullptr : &*found;
}

[[nodiscard]] inline const TrafficSelectorList *
find_traffic_selector_list(const std::vector<TrafficSelectorList> &lists,
                           std::string_view name) noexcept {
  const auto found = std::find_if(lists.begin(), lists.end(),
                                  [name](const auto &item) {
                                    return item.name == name;
                                  });
  return found == lists.end() ? nullptr : &*found;
}

[[nodiscard]] inline bool address_not_after(const ipsec::Address &left,
                                            const ipsec::Address &right) {
  return left.family == right.family &&
         !std::lexicographical_compare(right.bytes.begin(), right.bytes.end(),
                                       left.bytes.begin(), left.bytes.end());
}

[[nodiscard]] inline bool
validate_traffic_selector_entry(const TrafficSelectorEntry &entry,
                                bool allow_incomplete = false) noexcept {
  if (!entry.id || entry.id > profile::maximum_traffic_selectors_per_list)
    return false;
  const bool has_prefix = entry.prefix.has_value();
  const bool has_range = entry.range_begin && entry.range_end;
  // SR OS permits list creation before mandatory children are supplied. An
  // empty address choice is valid configuration intent but is never compiled
  // into an SPD selector. Half a range or both choices remain invalid.
  const bool half_address_range =
      entry.range_begin.has_value() != entry.range_end.has_value();
  if ((has_prefix && (has_range || half_address_range)) ||
      (!allow_incomplete && half_address_range))
    return false;
  if ((has_prefix && !valid_prefix(*entry.prefix)) ||
      (has_range &&
       (!valid_address(*entry.range_begin) ||
        !valid_address(*entry.range_end) ||
        !address_not_after(*entry.range_begin, *entry.range_end))))
    return false;
  if ((entry.protocol == SelectorProtocol::numeric &&
       !entry.numeric_protocol) ||
      (entry.numeric_protocol && !entry.protocol_configured))
    return false;
  // Port information exists in IKEv2 selectors for TCP, UDP and SCTP. Opaque
  // permits a selector when the port field is unavailable. Other protocols
  // must retain the full wildcard range.
  const bool range_protocol = entry.protocol == SelectorProtocol::tcp ||
                              entry.protocol == SelectorProtocol::udp ||
                              entry.protocol == SelectorProtocol::sctp ||
                              entry.protocol == SelectorProtocol::icmp ||
                              entry.protocol == SelectorProtocol::icmpv6 ||
                              entry.protocol == SelectorProtocol::ipv6_mobility;
  const bool icmp_protocol = entry.protocol == SelectorProtocol::icmp ||
                             entry.protocol == SelectorProtocol::icmpv6;
  const bool any_icmp_leaf = entry.begin_icmp_type_configured ||
                             entry.begin_icmp_code_configured ||
                             entry.end_icmp_type_configured ||
                             entry.end_icmp_code_configured;
  const bool all_icmp_leaves = entry.begin_icmp_type_configured &&
                               entry.begin_icmp_code_configured &&
                               entry.end_icmp_type_configured &&
                               entry.end_icmp_code_configured;
  const bool half_selector_range =
      entry.selector_begin_configured != entry.selector_end_configured;
  if ((!allow_incomplete && (half_selector_range ||
                             (any_icmp_leaf && !all_icmp_leaves))) ||
      (any_icmp_leaf && !icmp_protocol) ||
      (icmp_protocol && any_icmp_leaf &&
       (entry.selector_begin_configured || entry.selector_end_configured)) ||
      (!allow_incomplete && !entry.opaque_ports && !half_selector_range &&
       (!any_icmp_leaf || all_icmp_leaves) &&
       entry.ports.first > entry.ports.last) ||
      (!range_protocol &&
       (entry.opaque_ports || entry.selector_begin_configured ||
        entry.selector_end_configured || any_icmp_leaf ||
        entry.ports.first != 0U || entry.ports.last != 65'535U)) ||
      (entry.opaque_ports &&
       (entry.selector_begin_configured || entry.selector_end_configured ||
        any_icmp_leaf)))
    return false;
  return true;
}

[[nodiscard]] inline bool validate_traffic_selector_lists(
    const std::vector<TrafficSelectorList> &lists,
    bool allow_incomplete = false) noexcept {
  if (lists.size() > profile::maximum_traffic_selector_lists)
    return false;
  for (std::size_t index = 0; index < lists.size(); ++index) {
    const auto &list = lists[index];
    if (list.name.empty() || list.name.size() > 32U ||
        list.local.size() > profile::maximum_traffic_selectors_per_list ||
        list.remote.size() > profile::maximum_traffic_selectors_per_list ||
        std::any_of(lists.begin(), lists.begin() + index,
                    [&](const auto &other) { return other.name == list.name; }))
      return false;
    const auto valid_side = [allow_incomplete](const auto &entries) {
      for (std::size_t entry_index = 0; entry_index < entries.size();
           ++entry_index) {
        if (!validate_traffic_selector_entry(entries[entry_index],
                                             allow_incomplete) ||
            std::any_of(entries.begin(), entries.begin() + entry_index,
                        [&](const auto &other) {
                          return other.id == entries[entry_index].id;
                        }))
          return false;
      }
      return true;
    };
    if (!valid_side(list.local) || !valid_side(list.remote))
      return false;
  }
  return true;
}

} // namespace router::ipsec::configuration
