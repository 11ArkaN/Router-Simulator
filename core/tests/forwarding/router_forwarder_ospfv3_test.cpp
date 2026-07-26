// RouterForwarder OSPFv3 multicast and scoped-unicast cases. Each case owns
// its forwarding fixture and depends only on the shared wire-level test support.

#include "router_forwarder_test_support.hpp"

void router_forwarder_ospfv3_multicast_tests() {
  using namespace router;
  using namespace router::lab;

  auto forwarder = std::make_unique<RouterForwarder>();
  const packet::Mac local_mac{0x02U, 0U, 0U, 0U, 0x89U, 1U};
  const packet::Mac peer_mac{0x02U, 0U, 0U, 0U, 0x89U, 2U};
  const auto local_link_local = ip::parse_ipv6("fe80::1");
  const auto peer_link_local = ip::parse_ipv6("fe80::2");
  const auto second_link_local = ip::parse_ipv6("fe80::11");
  const auto second_peer_link_local = ip::parse_ipv6("fe80::22");
  const auto local_global = ip::parse_ipv6("2001:db8:89::1");
  const auto local_network = ip::parse_ipv6("2001:db8:89::");
  const auto second_global = ip::parse_ipv6("2001:db8:90::1");
  const auto second_network = ip::parse_ipv6("2001:db8:90::");
  require(local_link_local && peer_link_local && second_link_local &&
              second_peer_link_local && local_global && local_network &&
              second_global && second_network,
          "OSPFv3 multicast fixture has invalid link-local addresses");

  ForwardPort port{
      .configured = true,
      .operational = true,
      .ordinal = 0U,
      .mtu = 1514U,
      .speed_mbps = 10'000U,
      .mac = local_mac,
      .ipv6_configured = true,
      .ipv6_address = *local_global,
      .ipv6_network = *local_network,
      .ipv6_link_local = *local_link_local,
      .ipv6_prefix_length = 64U};
  require(forwarder->configure_port(port),
          "OSPFv3 multicast fixture rejected its physical port");
  auto second_port = port;
  second_port.ordinal = 1U;
  second_port.mac = {0x02U, 0U, 0U, 0U, 0x89U, 3U};
  second_port.ipv6_address = *second_global;
  second_port.ipv6_network = *second_network;
  second_port.ipv6_link_local = *second_link_local;
  require(forwarder->configure_port(second_port),
          "OSPFv3 scoped-unicast fixture rejected its second port");

  // A protocol-89 datagram is sufficient to prove the forwarding boundary:
  // decoding the OSPF payload belongs to the control shard after the punt.
  // The frame still carries the normative link-local source, ff02::5
  // destination, Hop Limit 1 and RFC 2464 multicast MAC mapping.
  constexpr std::array<std::uint8_t, 1U> payload{0U};
  packet::Frame hello{};
  const auto encoded = packet::encode_ipv6_ethernet_datagram(
      hello.bytes, peer_mac,
      packet::ipv6_multicast_mac(packet::ospf::all_spf_routers_v6),
      *peer_link_local, packet::ospf::all_spf_routers_v6,
      packet::ospf::ip_protocol, 1U, payload);
  require(encoded && *encoded <= hello.bytes.size(),
          "OSPFv3 multicast fixture could not encode its wire frame");
  hello.length = static_cast<std::uint16_t>(*encoded);

  std::vector<Emitted> emitted;
  std::size_t punts{};
  forwarder->receive(0U, hello, &emitted, collect,
                     RouterForwarder::Clock::now(), &punts, count_punt);
  require(punts == 0U,
          "OSPFv3 multicast reached CPM before interface punt programming");

  require(forwarder->configure_ospf_punt(0U, false, true),
          "OSPFv3 multicast fixture could not enable its punt projection");
  forwarder->receive(0U, hello, &emitted, collect,
                     RouterForwarder::Clock::now(), &punts, count_punt);
  require(punts == 1U && emitted.empty(),
          "OSPFv3 multicast did not cross the programmed forwarding-to-CPM "
          "boundary exactly once");

  // DAD is owned by the forwarding interface and must complete before an OSPF
  // link-local source can transmit. Explicit monotonic instants avoid sleeping
  // while preserving the required initial delay and RetransTimer waits.
  const auto dad_origin = RouterForwarder::Clock::now();
  for (std::size_t turn = 1U; turn <= 5U; ++turn)
    forwarder->service_ipv6_maintenance(
        &emitted, collect, dad_origin + std::chrono::seconds{turn});
  require(forwarder->ipv6_address_state(
              physical_interface_id(second_port.ordinal),
              second_port.ipv6_link_local) &&
              forwarder
                      ->ipv6_address_state(
                          physical_interface_id(second_port.ordinal),
                          second_port.ipv6_link_local)
                      ->state == Ipv6DadState::preferred,
          "OSPFv3 scoped-unicast fixture used a tentative link-local source");

  emitted.clear();
  packet::Frame description{};
  const auto description_octets = packet::encode_ipv6_ethernet_datagram(
      description.bytes, second_port.mac, {},
      second_port.ipv6_link_local, *second_peer_link_local,
      packet::ospf::ip_protocol, 1U, payload);
  require(description_octets.has_value(),
          "OSPFv3 scoped-unicast fixture could not encode its DD envelope");
  description.length = static_cast<std::uint16_t>(*description_octets);

  // The forwarder intentionally has no global fe80::/64 FIB entry. RFC 4007
  // assigns the destination to the protocol-selected interface zone, so the
  // first transmission must start ND on port 1 instead of performing an
  // ambiguous longest-prefix lookup or leaking onto port 0.
  require(forwarder->originate_ospf(
              second_port.ordinal, description, &emitted, collect,
              dad_origin + std::chrono::seconds{5}) &&
              emitted.size() == 1U && emitted.front().port == 1U &&
              packet::nd::parse_neighbor_solicitation(emitted.front().frame),
          "OSPFv3 unicast did not resolve its neighbor in the selected zone");

  emitted.clear();
  const auto advertisement = packet::nd::neighbor_advertisement(
      peer_mac, second_port.mac, *second_peer_link_local,
      second_port.ipv6_link_local, *second_peer_link_local, false, true, true);
  forwarder->receive(1U, advertisement, &emitted, collect,
                     dad_origin + std::chrono::seconds{5}, nullptr, nullptr);
  require(emitted.size() == 1U && emitted.front().port == 1U,
          "OSPFv3 DD did not leave through its interface after ND completed");
  const auto emitted_ipv6 = packet::parse_ipv6(emitted.front().frame);
  const auto emitted_ethernet = packet::parse_ethernet(emitted.front().frame);
  require(emitted_ipv6 && emitted_ethernet &&
              emitted_ipv6->destination == *second_peer_link_local &&
              emitted_ethernet->destination == peer_mac,
          "OSPFv3 DD did not use the resolved neighbor on its selected link");
}
