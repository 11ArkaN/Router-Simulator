// IPv6 value tests cover RFC 4291 parsing, RFC 5952 formatting, canonical
// prefix keys and multicast derivation without involving packet or device
// state. This keeps configuration text failures distinguishable from wire
// codec failures.

#include "router/ip_address.hpp"

#include <stdexcept>

void ip_address_tests() {
  using namespace router::ip;

  const auto documentation =
      parse_ipv6("2001:0db8:0000:0000:0000:ff00:0042:8329");
  if (!documentation || format_ipv6(*documentation) !=
                            "2001:db8::ff00:42:8329") {
    throw std::runtime_error("IPv6 canonical text formatting failed");
  }

  const auto loopback = parse_ipv6("::1");
  const auto unspecified = parse_ipv6("::");
  const auto mapped = parse_ipv6("::ffff:192.0.2.128");
  if (!loopback || !is_loopback(*loopback) || !unspecified ||
      !is_unspecified(*unspecified) || !mapped ||
      format_ipv6(*mapped) != "::ffff:c000:280") {
    throw std::runtime_error("Compressed or mixed IPv6 parsing failed");
  }

  // A parser used at a configuration boundary must reject ambiguous shapes,
  // zones without interface identity, too many words and out-of-range IPv4.
  if (parse_ipv6("2001::db8::1") || parse_ipv6("fe80::1%1") ||
      parse_ipv6("1:2:3:4:5:6:7:8:9") ||
      parse_ipv6("::ffff:192.0.2.999")) {
    throw std::runtime_error("Invalid IPv6 text was accepted");
  }

  const auto prefix = parse_ipv6_prefix("2001:db8::/32");
  const auto member = parse_ipv6("2001:db8:abcd::1");
  const auto outsider = parse_ipv6("2001:db9::1");
  if (!prefix || !member || !outsider || !contains(*prefix, *member) ||
      contains(*prefix, *outsider) ||
      parse_ipv6_prefix("2001:db8::1/32")) {
    throw std::runtime_error("IPv6 canonical prefix matching failed");
  }

  // SR OS policy-options accepts both address families in one prefix list.
  // The shared value must preserve family, canonical network bits and text so
  // a protocol-specific consumer can ignore the other family without losing
  // operator configuration from compare or checkpoint output.
  const auto generic_v4 = parse_ip_prefix("192.0.2.0/24");
  const auto generic_v6 = parse_ip_prefix("2001:db8::/32");
  const auto v4_member = parse_ip_address("192.0.2.99");
  const auto v4_outsider = parse_ip_address("198.51.100.1");
  if (!generic_v4 || !generic_v6 || !v4_member || !v4_outsider ||
      format_ip_prefix(*generic_v4) != "192.0.2.0/24" ||
      format_ip_prefix(*generic_v6) != "2001:db8::/32" ||
      !contains(*generic_v4, *v4_member) ||
      contains(*generic_v4, *v4_outsider) ||
      contains(*generic_v6, *v4_member) ||
      parse_ip_prefix("192.0.2.1/24") || parse_ip_prefix("192.0.2.0/33")) {
    throw std::runtime_error("Dual-stack canonical prefix handling failed");
  }

  const auto unicast = parse_ipv6("2001:db8::1234:5678");
  const auto solicited = unicast ? solicited_node_multicast(*unicast) : Ipv6{};
  if (!unicast || format_ipv6(solicited) != "ff02::1:ff34:5678") {
    throw std::runtime_error("Solicited-node multicast derivation failed");
  }

  // IEEE example-style octets make the inserted ff:fe and complemented U/L
  // bit visible in canonical text. DAD is tested separately by its state owner.
  const std::array<std::uint8_t, 6> mac{0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e};
  if (format_ipv6(link_local_from_mac(mac)) !=
      "fe80::21a:2bff:fe3c:4d5e") {
    throw std::runtime_error("Modified EUI-64 link-local derivation failed");
  }

  // The router interface eui-64 leaf uses the same IEEE-derived IID but keeps
  // the configured global /64. Candidate validation separately rejects host
  // bits in the list key because they would make checkpoint identity
  // ambiguous. Non-/64 EUI-64 formation is outside the SR OS leaf contract,
  // so the shared derivation helper rejects it directly.
  const auto global_prefix = parse_ipv6("2001:db8:1::");
  const auto global_eui64 =
      global_prefix ? address_from_eui64(*global_prefix, 64U, mac)
                    : std::optional<Ipv6>{};
  if (!global_eui64 ||
      format_ipv6(*global_eui64) != "2001:db8:1:0:21a:2bff:fe3c:4d5e" ||
      address_from_eui64(*global_prefix, 80U, mac)) {
    throw std::runtime_error("Router interface EUI-64 derivation failed");
  }
}
