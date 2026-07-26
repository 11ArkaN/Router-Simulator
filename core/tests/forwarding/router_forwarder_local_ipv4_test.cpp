// RouterForwarder local IPv4 delivery, reassembly and ICMP cases. The test
// owns one forwarding fixture and depends only on shared wire-level support.

#include "router_forwarder_test_support.hpp"

void router_forwarder_local_ipv4_delivery_tests() {
  using namespace router;
  using namespace router::lab;
  using namespace router::lab::routing;

  // This suite owns its forwarding object independently of the wider router
  // integration suite. Apart from making the behavioral boundary explicit,
  // that separation matters in WebAssembly: maximum-sized Frame fixtures are
  // short-lived packet buffers and must not inflate an unrelated test's single
  // control-stack frame for its entire two-thousand-line lifetime.
  auto forwarder = std::make_unique<RouterForwarder>();
  const packet::Mac router_mac{0x02, 0, 0, 0, 1, 1};
  const packet::Mac host_mac{0x02, 0, 0, 0, 0, 1};
  require(forwarder->configure_port({true, true, 0, 1514, 0x0a000001U,
                                     0x0a000000U, 10'000, 24, router_mac}),
          "local IPv4 suite could not configure its physical port");

  RouteTable rib;
  const std::array connected{ConnectedInput{true, true, 0x0a000000U, 0, 24},
                             ConnectedInput{.configured = true,
                                            .operational = true,
                                            .network = 0x0aff0001U,
                                            .prefix_length = 32U,
                                            .local_system = true}};
  require(rib.rebuild(connected, std::span<const StaticInput>{}) &&
              forwarder->program_fib(rib.compile(1U)),
          "local IPv4 suite could not program connected and system routes");

  std::vector<Emitted> emitted;
  // Learn the return adjacency from a real encoded ARP request. ICMP errors
  // below are therefore forced through the same FIB and ARP path as ordinary
  // router-originated traffic instead of using a test-only response shortcut.
  const auto reverse_arp =
      packet::arp_request(host_mac, {10, 0, 0, 2}, {10, 0, 0, 1});
  forwarder->receive(0U, reverse_arp, &emitted, collect);
  emitted.clear();

  // A router is a destination host for packets addressed to any of its own
  // interfaces. Deliver fragments out of order so parsing fragment zero as a
  // complete Echo Request cannot accidentally satisfy the test.
  const auto local_echo =
      packet::icmp_echo(host_mac, router_mac, {10, 0, 0, 2}, {10, 0, 0, 1},
                        false, 43U, 64U, 200U);
  const auto fragments = packet::fragment_ipv4(local_echo, 100U);
  require(fragments && fragments->count == 3U,
          "local IPv4 reassembly fixture did not produce three fragments");
  const auto fragment_now = RouterForwarder::Clock::now();
  forwarder->receive(0U, fragments->frames[2], &emitted, collect, fragment_now);
  forwarder->receive(0U, fragments->frames[1], &emitted, collect, fragment_now);
  require(emitted.empty(),
          "incomplete local IPv4 fragments reached the ICMP dispatcher");
  forwarder->receive(0U, fragments->frames[0], &emitted, collect, fragment_now);
  const auto local_reply = emitted.empty()
                               ? std::optional<packet::IcmpView>{}
                               : packet::parse_icmp(emitted.back().frame);
  require(emitted.size() == 1U && emitted.back().port == 0U && local_reply &&
              local_reply->type == 0U && local_reply->sequence == 43U,
          "router-local IPv4 reassembly did not produce one Echo Reply");

  // Preserve an incomplete set through a checkpoint, then let the restored
  // owner expire it. Only fragment zero permits the mandatory code 1 report.
  emitted.clear();
  forwarder->receive(0U, fragments->frames[0], &emitted, collect, fragment_now);
  const auto checkpoint = snapshot(*forwarder, fragment_now);
  require(checkpoint->ipv4_reassembly.size() == 1U,
          "router checkpoint omitted local IPv4 reassembly state");
  auto restored = std::make_unique<RouterForwarder>();
  require(restored->restore(*checkpoint, fragment_now),
          "router rejected valid IPv4 reassembly checkpoint state");
  restored->service_ipv4_maintenance(
      &emitted, collect,
      fragment_now + device_catalog::ipv4_reassembly_timeout);
  const auto reassembly_timeout =
      emitted.empty() ? std::optional<packet::IcmpView>{}
                      : packet::parse_icmp(emitted.back().frame);
  require(emitted.size() == 1U && reassembly_timeout &&
              reassembly_timeout->type == 11U && reassembly_timeout->code == 1U,
          "restored local IPv4 reassembly timeout omitted ICMP code 1");

  // Fragment zero is also sufficient to identify an invoking ICMP error. Its
  // checksum necessarily spans bytes that have not arrived, so the router must
  // inspect only the available type for the RFC 1812 recursion prohibition and
  // silently reclaim the timed-out entry rather than answer one error with
  // another error.
  emitted.clear();
  const auto invoking_error = packet::icmp_network_unreachable(
      local_echo, host_mac, router_mac, {10, 0, 0, 2}, {10, 0, 0, 1});
  const auto error_fragments = invoking_error
                                   ? packet::fragment_ipv4(*invoking_error, 44U)
                                   : std::nullopt;
  require(error_fragments && error_fragments->count > 1U,
          "ICMP error suppression fixture was not fragmented");
  const auto error_fragment_now = fragment_now +
                                  device_catalog::ipv4_reassembly_timeout +
                                  std::chrono::seconds{1};
  // Use the restored owner whose earlier incomplete set has already expired.
  // The original owner intentionally still contains the checkpoint source
  // set, which would independently and correctly emit its own timeout here.
  restored->receive(0U, error_fragments->frames[0], &emitted, collect,
                    error_fragment_now);
  restored->service_ipv4_maintenance(
      &emitted, collect,
      error_fragment_now + device_catalog::ipv4_reassembly_timeout);
  require(emitted.empty(),
          "IPv4 reassembly timeout replied to an invoking ICMP error");

  // UDP reaches the forwarding owner's real socket table. With no bound
  // destination port the router returns code 3. An unowned IP Protocol value
  // returns code 2. Both errors use the independently resolved reverse route.
  emitted.clear();
  std::array<std::uint8_t, 64U> udp_bytes{};
  constexpr std::array<std::uint8_t, 4U> udp_payload{1U, 2U, 3U, 4U};
  const auto udp_octets = packet::udp::encode_ipv4(
      udp_bytes, {10, 0, 0, 2}, {10, 0, 0, 1}, 40'000U, 53U, udp_payload);
  std::array<std::uint8_t, packet::maximum_frame_octets> storage{};
  const auto udp_frame_octets =
      udp_octets
          ? packet::encode_ipv4_ethernet_datagram(
                storage, host_mac, router_mac, {10, 0, 0, 2}, {10, 0, 0, 1},
                17U, 64U, 7U,
                std::span<const std::uint8_t>{udp_bytes}.first(*udp_octets),
                false)
          : std::nullopt;
  packet::Frame closed_udp_frame;
  if (udp_frame_octets) {
    std::copy_n(storage.begin(), *udp_frame_octets,
                closed_udp_frame.bytes.begin());
    closed_udp_frame.length = static_cast<std::uint16_t>(*udp_frame_octets);
  }
  forwarder->receive(0U, closed_udp_frame, &emitted, collect);
  const auto closed_port = emitted.empty()
                               ? std::optional<packet::IcmpView>{}
                               : packet::parse_icmp(emitted.back().frame);
  require(udp_frame_octets && emitted.size() == 1U && closed_port &&
              closed_port->type == 3U && closed_port->code == 3U,
          "router-local closed UDP port omitted ICMP code 3");

  // RFC 2644 disables receipt and forwarding of a subnet-directed broadcast
  // by default. It must not become a connected route that ARPs for .255, an
  // ICMP error, or an Echo response.
  emitted.clear();
  constexpr packet::Mac broadcast_mac{0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU};
  const auto broadcast_udp_octets = packet::encode_ipv4_ethernet_datagram(
      storage, host_mac, broadcast_mac, {10, 0, 0, 2}, {10, 0, 0, 255}, 17U,
      64U, 9U, std::span<const std::uint8_t>{udp_bytes}.first(*udp_octets),
      false);
  packet::Frame broadcast_udp;
  if (broadcast_udp_octets) {
    std::copy_n(storage.begin(), *broadcast_udp_octets,
                broadcast_udp.bytes.begin());
    broadcast_udp.length = static_cast<std::uint16_t>(*broadcast_udp_octets);
  }
  forwarder->receive(0U, broadcast_udp, &emitted, collect);
  const auto broadcast_echo =
      packet::icmp_echo(host_mac, broadcast_mac, {10, 0, 0, 2}, {10, 0, 0, 255},
                        false, 44U, 64U, 8U);
  forwarder->receive(0U, broadcast_echo, &emitted, collect);
  require(broadcast_udp_octets && emitted.empty(),
          "router forwarded or answered IPv4 subnet broadcast input");
  require(forwarder->last_drop() ==
              lab::ForwardDrop::directed_broadcast_disabled,
          "directed broadcast was misclassified as malformed input");

  emitted.clear();
  constexpr std::array<std::uint8_t, 8U> unknown_payload{};
  const auto unknown_octets = packet::encode_ipv4_ethernet_datagram(
      storage, host_mac, router_mac, {10, 0, 0, 2}, {10, 0, 0, 1}, 99U, 64U, 8U,
      unknown_payload, false);
  packet::Frame unknown_protocol;
  if (unknown_octets) {
    std::copy_n(storage.begin(), *unknown_octets,
                unknown_protocol.bytes.begin());
    unknown_protocol.length = static_cast<std::uint16_t>(*unknown_octets);
  }
  forwarder->receive(0U, unknown_protocol, &emitted, collect);
  const auto unsupported_protocol =
      emitted.empty() ? std::optional<packet::IcmpView>{}
                      : packet::parse_icmp(emitted.back().frame);
  require(unknown_octets && emitted.size() == 1U && unsupported_protocol &&
              unsupported_protocol->type == 3U &&
              unsupported_protocol->code == 2U,
          "router-local unknown IPv4 protocol omitted ICMP code 2");

  // Read counters only after exercising the actual packet path. This guards
  // against an attractive but incorrect implementation where show commands
  // synthesize plausible values independently of admitted wire traffic.
  const auto global_statistics = forwarder->icmpv4_global_statistics();
  const auto interface_statistics = forwarder->icmpv4_interface_statistics(0U);
  require(interface_statistics.has_value() &&
              global_statistics.received.total == 1U &&
              global_statistics.received.echo_request == 1U &&
              global_statistics.sent.total == 3U &&
              global_statistics.sent.echo_reply == 1U &&
              global_statistics.sent.destination_unreachable == 2U &&
              *interface_statistics == global_statistics,
          "local IPv4 wire traffic did not drive scoped ICMP counters");

  // The timeout was emitted by the independently restored owner. Its state
  // must contain the earlier Echo exchange from the checkpoint plus exactly
  // one code 1 Time Exceeded generated after restore.
  const auto restored_statistics = restored->icmpv4_global_statistics();
  require(restored_statistics.received.echo_request == 1U &&
              restored_statistics.sent.echo_reply == 1U &&
              restored_statistics.sent.time_exceeded == 1U &&
              restored_statistics.sent.total == 2U,
          "checkpointed ICMP counters or restored timeout accounting diverged");

  // Global, interface and all are separate operational scopes in SR OS. Clear
  // through the forwarding owner and prove that each operation leaves every
  // non-selected scope intact. An absent physical ordinal must be rejected.
  const auto before_global_clear = restored->icmpv4_interface_statistics(0U);
  restored->clear_icmpv4_global_statistics();
  require(restored->icmpv4_global_statistics() == Icmpv4Statistics{} &&
              restored->icmpv4_interface_statistics(0U) == before_global_clear,
          "global ICMP clear changed independent interface statistics");
  require(restored->clear_icmpv4_interface_statistics(0U) &&
              restored->icmpv4_interface_statistics(0U) == Icmpv4Statistics{} &&
              !restored->clear_icmpv4_interface_statistics(799U),
          "interface ICMP clear accepted an absent port or retained data");
  restored->clear_icmpv4_statistics_all();
  require(restored->icmpv4_global_statistics() == Icmpv4Statistics{} &&
              restored->icmpv4_interface_statistics(0U) == Icmpv4Statistics{},
          "all ICMP clear retained a counter scope");
}
