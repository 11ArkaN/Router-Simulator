// RouterForwarder IPv4 Redirect policy and limiter cases. The test owns one
// forwarding fixture and depends only on shared wire-level support.

#include "router_forwarder_test_support.hpp"

void router_forwarder_ipv4_redirect_tests() {
  using namespace router;
  using namespace router::lab;
  using namespace router::lab::routing;

  auto forwarder = std::make_unique<RouterForwarder>();
  constexpr packet::Mac router_mac{0x02U, 0U, 0U, 0U, 1U, 1U};
  constexpr packet::Mac host_mac{0x02U, 0U, 0U, 0U, 0U, 2U};
  constexpr packet::Mac gateway_mac{0x02U, 0U, 0U, 0U, 0U, 3U};
  ForwardPort port{.configured = true,
                   .operational = true,
                   .ordinal = 0U,
                   .mtu = 1514U,
                   .address = 0x0a000001U,
                   .network = 0x0a000000U,
                   .speed_mbps = 10'000U,
                   .prefix_length = 24U,
                   .mac = router_mac,
                   .icmp_redirect_maximum = 10U,
                   .icmp_redirect_interval_seconds = 1U};
  require(forwarder->configure_port(port),
          "IPv4 Redirect fixture rejected its interface policy");
  RouteTable rib;
  const std::array connected{ConnectedInput{true, true, 0x0a000000U, 0U, 24U}};
  const std::array statics{StaticInput{true, 0xc0000200U, 0x0a000003U, 24U}};
  require(rib.rebuild(connected, statics) &&
              forwarder->program_fib(rib.compile(1U)),
          "IPv4 Redirect fixture rejected connected and static routes");

  std::vector<Emitted> emitted;
  // Learn the better router from encoded ARP. The invoking datagram can then
  // be forwarded while the independent Redirect returns directly to the
  // source MAC observed on the ingress link.
  const auto gateway_arp =
      packet::arp_request(gateway_mac, {10, 0, 0, 3}, {10, 0, 0, 1});
  forwarder->receive(0U, gateway_arp, &emitted, collect);
  emitted.clear();
  const auto invoking = packet::icmp_echo(host_mac, router_mac, {10, 0, 0, 2},
                                          {192, 0, 2, 9}, false, 77U);
  const auto now = RouterForwarder::Clock::now();
  forwarder->receive(0U, invoking, &emitted, collect, now);
  const auto redirect =
      std::find_if(emitted.begin(), emitted.end(), [](const auto &candidate) {
        const auto icmp = packet::parse_icmp(candidate.frame);
        return icmp && icmp->type == 5U && icmp->code == 1U;
      });
  const auto redirect_ip = redirect == emitted.end()
                               ? std::optional<packet::Ipv4View>{}
                               : packet::parse_ipv4(redirect->frame);
  const auto redirect_ethernet = redirect == emitted.end()
                                     ? std::optional<packet::EthernetView>{}
                                     : packet::parse_ethernet(redirect->frame);
  require(redirect != emitted.end() && redirect_ip && redirect_ethernet &&
              redirect->port == 0U &&
              redirect_ip->source == packet::Ipv4{10, 0, 0, 1} &&
              redirect_ip->destination == packet::Ipv4{10, 0, 0, 2} &&
              redirect_ethernet->source == router_mac &&
              redirect_ethernet->destination == host_mac &&
              std::equal(redirect->frame.bytes.begin() + 38U,
                         redirect->frame.bytes.begin() + 42U,
                         packet::Ipv4{10, 0, 0, 3}.begin()),
          "IPv4 Host Redirect carried an incorrect gateway or return envelope");

  // The configured fixed window admits ten messages. Transit forwarding is
  // independent and therefore continues for the eleventh invoking packet.
  emitted.clear();
  for (std::uint16_t sequence = 0U; sequence < 11U; ++sequence) {
    const auto request = packet::icmp_echo(host_mac, router_mac, {10, 0, 0, 2},
                                           {192, 0, 2, 9}, false, sequence);
    forwarder->receive(0U, request, &emitted, collect,
                       now + std::chrono::milliseconds{10});
  }
  const auto redirects =
      std::count_if(emitted.begin(), emitted.end(), [](const auto &candidate) {
        const auto icmp = packet::parse_icmp(candidate.frame);
        return icmp && icmp->type == 5U;
      });
  require(redirects == 9U && emitted.size() == 20U,
          "IPv4 Redirect limiter altered transit or exceeded its window");

  const auto checkpoint =
      snapshot(*forwarder, now + std::chrono::milliseconds{10});
  require(checkpoint->ipv4_redirect_limiters.size() == 1U &&
              checkpoint->ipv4_redirect_limiters[0].sent == 10U,
          "IPv4 Redirect fixed window was absent from checkpoint state");
  auto restored = std::make_unique<RouterForwarder>();
  require(restored->restore(*checkpoint, now + std::chrono::milliseconds{10}),
          "IPv4 Redirect fixed window did not restore");
  emitted.clear();
  restored->receive(0U, invoking, &emitted, collect,
                    now + std::chrono::milliseconds{20});
  require(std::none_of(emitted.begin(), emitted.end(),
                       [](const auto &candidate) {
                         const auto icmp = packet::parse_icmp(candidate.frame);
                         return icmp && icmp->type == 5U;
                       }) &&
              emitted.size() == 1U,
          "restored IPv4 Redirect limiter forgot its active allowance");

  port.icmp_redirects_enabled = false;
  require(restored->configure_port(port),
          "IPv4 Redirect disable policy was rejected");
  emitted.clear();
  restored->receive(0U, invoking, &emitted, collect,
                    now + std::chrono::seconds{2});
  require(emitted.size() == 1U,
          "disabled IPv4 Redirect policy changed ordinary forwarding");
}
