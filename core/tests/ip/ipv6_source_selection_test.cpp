// RFC 6724 rule-order tests. Addresses are parsed from their standards-facing
// representation so fixtures also guard integration with the canonical codec.

#include "router/ipv6_source_selection.hpp"

#include <array>
#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

router::ip::Ipv6 address(const char *text) {
  const auto parsed = router::ip::parse_ipv6(text);
  if (!parsed)
    throw std::runtime_error("source-selection fixture address is invalid");
  return *parsed;
}

} // namespace

void ipv6_source_selection_tests() {
  using namespace router::ip;
  require(ipv6_scope(address("fe80::1")) == Ipv6Scope::link_local &&
              ipv6_scope(address("ff05::1")) == Ipv6Scope::site_local &&
              ipv6_scope(address("fd00::1")) == Ipv6Scope::global,
          "IPv6 scope classification disagrees with RFC 6724");
  require(ipv6_policy_label(address("2002::1")) == 2U &&
              ipv6_policy_label(address("fd00::1")) == 13U &&
              ipv6_policy_label(address("2001:db8::1")) == 1U,
          "default source policy did not use longest-prefix labels");

  const std::array candidates{
      Ipv6SourceCandidate{.address = address("fe80::2"),
                          .interface_id = 7,
                          .prefix_length = 64},
      Ipv6SourceCandidate{.address = address("2001:db8:2::2"),
                          .interface_id = 7,
                          .prefix_length = 64},
      Ipv6SourceCandidate{.address = address("2001:db8:1::2"),
                          .interface_id = 7,
                          .prefix_length = 64}};
  auto selected = select_ipv6_source(
      candidates, {.destination = address("2001:db8:1::1"),
                   .outgoing_interface_id = 7});
  require(selected && *selected == 2U,
          "appropriate scope and longest prefix did not select global source");

  auto deprecated = candidates;
  deprecated[2].preferred = false;
  selected = select_ipv6_source(
      deprecated, {.destination = address("2001:db8:1::1"),
                   .outgoing_interface_id = 7});
  require(selected && *selected == 1U,
          "deprecated source won before longest-prefix tiebreaking");

  auto same = deprecated;
  same[2].address = address("2001:db8:1::1");
  selected = select_ipv6_source(
      same, {.destination = address("2001:db8:1::1"),
             .outgoing_interface_id = 7});
  require(selected && *selected == 2U,
          "same-address rule did not precede deprecation rule");

  auto cross_link = candidates;
  for (auto &candidate : cross_link)
    candidate.interface_id = 8;
  selected = select_ipv6_source(
      cross_link, {.destination = address("fe80::9"),
                   .outgoing_interface_id = 7});
  require(!selected,
          "link-local destination accepted source from a different zone");
}
