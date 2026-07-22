// Neighbor Discovery wire tests verify that address resolution and DAD are
// represented by real ICMPv6 frames with hop limit, options and checksums. No
// test passes a neighbor object directly between endpoints.

#include "router/neighbor_discovery_packet.hpp"

#include <algorithm>
#include <stdexcept>

void neighbor_discovery_packet_tests() {
  using namespace router::packet;
  using namespace router::packet::nd;
  const Mac source_mac{0x02, 0, 0, 0, 0, 1};
  const Mac target_mac{0x02, 0, 0, 0, 0, 2};
  const auto source = router::ip::parse_ipv6("2001:db8:1::1");
  const auto target = router::ip::parse_ipv6("2001:db8:1::2");
  if (!source || !target)
    throw std::runtime_error("ND test address setup failed");

  const auto solicitation = neighbor_solicitation(source_mac, *source, *target);
  const auto solicitation_ip = parse_ipv6(solicitation);
  const auto parsed_solicitation =
      parse_neighbor_solicitation(solicitation);
  const auto expected_destination =
      router::ip::solicited_node_multicast(*target);
  const auto ethernet = parse_ethernet(solicitation);
  if (!solicitation_ip || !parsed_solicitation || !ethernet ||
      solicitation_ip->hop_limit != 255U ||
      solicitation_ip->destination != expected_destination ||
      ethernet->destination != ipv6_multicast_mac(expected_destination) ||
      parsed_solicitation->target != *target ||
      parsed_solicitation->source_link_layer != source_mac ||
      parsed_solicitation->duplicate_address_detection) {
    throw std::runtime_error("Neighbor Solicitation encoding failed");
  }

  const auto dad = neighbor_solicitation(source_mac, *source, *target, true);
  const auto parsed_dad = parse_neighbor_solicitation(dad);
  if (!parsed_dad || !parsed_dad->duplicate_address_detection ||
      parsed_dad->source_link_layer ||
      !router::ip::is_unspecified(parsed_dad->source)) {
    throw std::runtime_error("DAD Neighbor Solicitation encoding failed");
  }

  const auto advertisement = neighbor_advertisement(
      target_mac, source_mac, *target, *source, *target, true, true, true);
  const auto parsed_advertisement =
      parse_neighbor_advertisement(advertisement);
  if (!parsed_advertisement || parsed_advertisement->target != *target ||
      parsed_advertisement->target_link_layer != target_mac ||
      !parsed_advertisement->router || !parsed_advertisement->solicited ||
      !parsed_advertisement->override_flag) {
    throw std::runtime_error("Neighbor Advertisement encoding failed");
  }

  // RFC 4861 requires hop limit 255 so a packet cannot have crossed a router.
  // Recompute is unnecessary because Hop Limit is outside the ICMPv6 checksum.
  auto off_link = solicitation;
  off_link.bytes[21] = 254;
  if (parse_neighbor_solicitation(off_link)) {
    throw std::runtime_error("Off-link Neighbor Solicitation was accepted");
  }

  // A solicited advertisement may not use a multicast IPv6 destination. This
  // semantic check remains separate from the valid checksum and packet shape.
  const auto all_nodes = router::ip::parse_ipv6("ff02::1");
  if (!all_nodes)
    throw std::runtime_error("ND all-nodes address setup failed");
  const auto invalid_advertisement = neighbor_advertisement(
      target_mac, ipv6_multicast_mac(*all_nodes), *target, *all_nodes, *target,
      false, true, true);
  if (parse_neighbor_advertisement(invalid_advertisement)) {
    throw std::runtime_error("Solicited multicast advertisement was accepted");
  }

  // Router discovery is exercised as wire traffic, including the distinct
  // unspecified-source RS form and every RA option currently consumed by the
  // SLAAC state owner. This catches layout drift before state-machine tests.
  const auto router_link_local = router::ip::parse_ipv6("fe80::1");
  const auto advertised_prefix = router::ip::parse_ipv6_prefix("2001:db8:42::/64");
  const auto dns_server = router::ip::parse_ipv6("2001:db8:42::53");
  if (!router_link_local || !advertised_prefix || !dns_server)
    throw std::runtime_error("Router Advertisement test setup failed");

  const auto rs = router_solicitation(source_mac, *source);
  const auto parsed_rs = parse_router_solicitation(rs);
  if (!parsed_rs || parsed_rs->source != *source ||
      parsed_rs->destination != all_routers_multicast ||
      parsed_rs->source_link_layer != source_mac)
    throw std::runtime_error("Router Solicitation encoding failed");
  const Ipv6 unspecified{};
  const auto initial_rs = router_solicitation(source_mac, unspecified);
  const auto parsed_initial_rs = parse_router_solicitation(initial_rs);
  if (!parsed_initial_rs || parsed_initial_rs->source_link_layer)
    throw std::runtime_error("Unspecified Router Solicitation carried SLLA");

  RouterAdvertisementConfig ra_config{
      .reachable_time_milliseconds = 30'000U,
      .retrans_timer_milliseconds = 1'000U,
      .router_lifetime_seconds = 1'800U,
      .advertised_mtu = 1'500U,
      .prefix_count = 1U,
      .current_hop_limit = 64U,
      .preference = RouterPreference::high,
      .managed_configuration = true,
      .other_configuration = true};
  ra_config.prefixes[0] = PrefixInformation{
      .prefix = *advertised_prefix,
      .valid_lifetime_seconds = 86'400U,
      .preferred_lifetime_seconds = 14'400U,
      .on_link = true,
      .autonomous = true};
  ra_config.rdnss.count = 1U;
  ra_config.rdnss_lifetime_seconds = 1'200U;
  ra_config.rdnss.servers[0] =
      RdnssServer{.address = *dns_server, .lifetime_seconds = 1'200U};
  const auto ra = router_advertisement(source_mac, *router_link_local,
                                       all_nodes_multicast, ra_config);
  const auto parsed_ra = ra ? parse_router_advertisement(*ra) : std::nullopt;
  if (!parsed_ra || parsed_ra->source != *router_link_local ||
      parsed_ra->destination != all_nodes_multicast ||
      parsed_ra->source_link_layer != source_mac ||
      parsed_ra->advertised_mtu != 1'500U ||
      parsed_ra->prefix_count != 1U || parsed_ra->rdnss.count != 1U ||
      parsed_ra->prefixes[0].prefix != *advertised_prefix ||
      parsed_ra->rdnss.servers[0].address != *dns_server ||
      parsed_ra->rdnss.servers[0].lifetime_seconds != 1'200U ||
      parsed_ra->preference != RouterPreference::high ||
      !parsed_ra->managed_configuration || !parsed_ra->other_configuration)
    throw std::runtime_error("Router Advertisement round trip failed");

  // Redirect is a complete wire message and quotes the invoking IPv6 packet.
  // The parser deliberately leaves only the current-first-hop check to the
  // host Destination Cache owner because that condition depends on live state.
  const auto remote = router::ip::parse_ipv6("2001:db8:99::9");
  const auto better_router = router::ip::parse_ipv6("fe80::2");
  if (!remote || !better_router)
    throw std::runtime_error("Redirect test address setup failed");
  const auto invoking = icmpv6_echo(source_mac, target_mac, *source, *remote,
                                    false, 17U);
  const auto redirect_frame = redirect(
      source_mac, target_mac, *router_link_local, *source, *better_router,
      *remote, target_mac, invoking);
  const auto parsed_redirect =
      redirect_frame ? parse_redirect(*redirect_frame) : std::nullopt;
  const auto redirect_ip =
      redirect_frame ? parse_ipv6(*redirect_frame) : std::nullopt;
  if (!parsed_redirect || !redirect_ip ||
      parsed_redirect->source != *router_link_local ||
      parsed_redirect->receiver != *source ||
      parsed_redirect->target != *better_router ||
      parsed_redirect->destination != *remote ||
      parsed_redirect->target_link_layer != target_mac ||
      !parsed_redirect->redirected_header_present ||
      ethernet_header_octets + ipv6_header_octets +
              redirect_ip->payload_length >
          ethernet_header_octets + ipv6_minimum_link_mtu)
    throw std::runtime_error("Redirect encoding or validation failed");
  auto off_link_redirect = *redirect_frame;
  off_link_redirect.bytes[21] = required_hop_limit - 1U;
  if (parse_redirect(off_link_redirect))
    throw std::runtime_error("Off-link Redirect was accepted");
  if (redirect(source_mac, target_mac, *source, *source, *better_router,
               *remote, target_mac, invoking) ||
      redirect(source_mac, target_mac, *router_link_local, *source, *target,
               *remote, target_mac, invoking))
    throw std::runtime_error("Invalid Redirect sender or target was encoded");

  // RFC 6980 includes atomic fragments in its prohibition. Insert a valid
  // offset-zero, M-zero Fragment Header without changing the ICMPv6 bytes or
  // checksum, then verify that the ND decoder ignores the complete packet.
  auto fragmented_ra = *ra;
  const auto payload_length = static_cast<std::uint16_t>(
      (fragmented_ra[18] << 8U) | fragmented_ra[19]);
  std::copy_backward(fragmented_ra.bytes.begin() + 54U,
                     fragmented_ra.bytes.begin() + 54U + payload_length,
                     fragmented_ra.bytes.begin() + 62U + payload_length);
  fragmented_ra.bytes[20] = 44U;
  fragmented_ra.bytes[54] = ipv6_next_header_icmpv6;
  fragmented_ra.bytes[55] = 0U;
  fragmented_ra.bytes[56] = 0U;
  fragmented_ra.bytes[57] = 0U;
  fragmented_ra.bytes[58] = 0x12U;
  fragmented_ra.bytes[59] = 0x34U;
  fragmented_ra.bytes[60] = 0x56U;
  fragmented_ra.bytes[61] = 0x78U;
  const auto fragmented_payload =
      static_cast<std::uint16_t>(payload_length + 8U);
  fragmented_ra.bytes[18] =
      static_cast<std::uint8_t>(fragmented_payload >> 8U);
  fragmented_ra.bytes[19] = static_cast<std::uint8_t>(fragmented_payload);
  fragmented_ra.length =
      static_cast<std::uint16_t>(fragmented_ra.length + 8U);
  if (parse_router_advertisement(fragmented_ra))
    throw std::runtime_error("fragmented Router Advertisement was accepted");

  // An encoder must reject local intent that would produce an invalid RA. It
  // cannot emit a packet and rely on the receiving side to mask a bad config.
  auto invalid_ra = ra_config;
  invalid_ra.prefixes[0].preferred_lifetime_seconds =
      invalid_ra.prefixes[0].valid_lifetime_seconds + 1U;
  if (router_advertisement(source_mac, *router_link_local,
                           all_nodes_multicast, invalid_ra))
    throw std::runtime_error("Invalid RA lifetime was encoded");
}
